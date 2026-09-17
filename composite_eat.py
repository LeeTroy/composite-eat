#!/usr/bin/env python3
"""Fetch a Composite EAT bundle from an OpenBMC Redfish service.

Flow (repeated `--loop` times):
  1. GET  /redfish/v1/ComponentIntegrity/
  2. GET  /redfish/v1/ComponentIntegrity/Oem/OpenBMC/CompositeEATBundle/
         wait until status is Ready or Idle
  3. POST /redfish/v1/ComponentIntegrity/Actions/Oem/OpenBMC.GetCompositeEATBundle
         with a freshly generated random 32 byte base64 nonce
  4. GET  the bundle resource until status is Ready, then base64+CBOR decode
         the "Bundle" property and print it.
"""

import argparse
import base64
import collections.abc
import datetime
import json
import os
import secrets
import sys
import time

import cbor2
import requests
import urllib3

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
except ImportError:  # --decode-certs is simply unavailable then
    x509 = None

COLLECTION_PATH = "/redfish/v1/ComponentIntegrity/"
BUNDLE_PATH = "/redfish/v1/ComponentIntegrity/Oem/OpenBMC/CompositeEATBundle/"
ACTION_PATH = (
    "/redfish/v1/ComponentIntegrity/Actions/Oem/OpenBMC.GetCompositeEATBundle"
)

READY_STATES = ("ready",)
IDLE_STATES = ("idle",)
BUSY_STATES = ("inprogress", "in progress", "running")


class RedfishError(RuntimeError):
    """Raised when the service answers with something unusable."""


def log(msg, *, quiet=False):
    if not quiet:
        print(msg, flush=True)


class RedfishClient:
    def __init__(self, host, user, password, *, scheme="https", port=None,
                 verify=False, timeout=30):
        netloc = host if port is None else f"{host}:{port}"
        self.base = f"{scheme}://{netloc}"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.verify = verify
        self.session.headers.update({"Accept": "application/json"})
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get(self, path):
        return self._request("GET", path)

    def post(self, path, payload):
        return self._request("POST", path, json=payload)

    def _request(self, method, path, **kwargs):
        url = self.base + path
        resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
        if resp.status_code >= 400:
            raise RedfishError(
                f"{method} {path} -> HTTP {resp.status_code}: {resp.text[:400]}"
            )
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            raise RedfishError(f"{method} {path} -> non-JSON body: {resp.text[:200]}")


def pick(data, *keys):
    """Return the first present key from a Redfish body."""
    for key in keys:
        if key in data:
            return data[key]
    return None


def bundle_blob(body):
    """Return the base64 bundle string, whatever the service calls it."""
    return pick(body, "CompositeEATBundle", "Bundle", "EATBundle")


def bundle_status(body):
    value = pick(body, "Status", "BundleStatus", "TaskState")
    if isinstance(value, dict):
        value = pick(value, "State", "Status")
    return value


def normalize(status):
    return str(status).strip().lower() if status is not None else ""


def show_collection(body, quiet=False):
    members = body.get("Members") or []
    log("  Name           : %s" % body.get("Name", "-"), quiet=quiet)
    log("  Members@count  : %s" % body.get("Members@odata.count", len(members)),
        quiet=quiet)
    for member in members:
        log("  Member         : %s" % member.get("@odata.id", member), quiet=quiet)


def show_bundle_resource(body, quiet=False):
    log("  Id             : %s" % body.get("Id", "-"), quiet=quiet)
    log("  Status         : %s" % (bundle_status(body) or "-"), quiet=quiet)
    if "Nonce" in body:
        log("  Nonce          : %s" % body["Nonce"], quiet=quiet)
    bundle = bundle_blob(body)
    if bundle:
        log("  Bundle length  : %d (base64 chars)" % len(bundle), quiet=quiet)


def decode_bundle(b64_bundle):
    raw = base64.b64decode(b64_bundle, validate=False)
    return raw, cbor2.loads(raw)


# --- label tables for the concise dump -------------------------------------

COSE_ALG = {-7: "ES256", -8: "EdDSA", -35: "ES384", -36: "ES512",
            -37: "PS256", -38: "PS384", -39: "PS512"}
COSE_HASH = {-14: "SHA-1", -16: "SHA-256", -43: "SHA-384", -44: "SHA-512"}
COSE_HDR = {1: "alg", 2: "crit", 3: "content type", 4: "kid", 5: "IV",
            32: "x5bag", 33: "x5chain", 34: "x5t", 35: "x5u"}
CWT_CLAIM = {
    1: "iss", 2: "sub", 3: "aud", 4: "exp", 5: "nbf", 6: "iat", 7: "cti",
    10: "nonce", 256: "ueid", 257: "sueids", 258: "oemid", 259: "hwmodel",
    260: "hwversion", 262: "oemboot", 263: "dbgstat", 264: "location",
    265: "profile", 266: "submods", 267: "uptime", 268: "bootcount",
    269: "bootseed", 271: "dloas", 272: "manifests", 273: "measurements",
    274: "measres", 275: "intuse",
}
CBOR_TAG_NAME = {18: "COSE_Sign1", 61: "CWT", 602: "Detached EAT Bundle",
                 1668546817: "COSE_Sign1 (tagged)"}
CONTENT_FORMAT = {0: "text/plain", 50: "application/json",
                  60: "application/cbor", 61: "application/cwt"}


def nested_cbor(raw):
    """Decode a byte string that itself holds CBOR, else return None.

    Composite EAT bundles nest CWT/COSE tokens as byte strings, so unwrapping
    them turns an opaque base64 blob into readable claims.
    """
    if len(raw) < 2:
        return None
    try:
        inner = cbor2.loads(raw)
    except Exception:
        return None
    if not isinstance(inner, (cbor2.CBORTag, collections.abc.Mapping,
                              list, tuple)):
        return None
    try:
        if cbor2.dumps(inner) != raw:  # trailing junk: not really CBOR
            return None
    except Exception:
        return None
    return inner


def jsonable(obj, *, recurse=True, depth=12, truncate=None):
    """Make CBOR output printable as JSON (bytes -> base64, keys -> str).

    `truncate` caps every leaf field at that many bytes/characters and marks
    the shortened value with a trailing "...".
    """
    if depth <= 0:
        return "<max depth>"
    kw = {"recurse": recurse, "depth": depth - 1, "truncate": truncate}
    if isinstance(obj, bytes):
        if recurse:
            inner = nested_cbor(obj)
            if inner is not None:
                return {"__cbor__": jsonable(inner, **kw)}
        key = "__bytes_b64__" if BYTES_ENC == "base64" else "__bytes_hex__"
        if truncate is not None and len(obj) > truncate:
            return {key: encode_bytes(obj[:truncate]) + "...",
                    "__bytes_len__": len(obj)}
        return {key: encode_bytes(obj)}
    if isinstance(obj, collections.abc.Mapping):
        return {str(jsonable(k, **kw)): jsonable(v, **kw) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [jsonable(v, **kw) for v in obj]
    if isinstance(obj, cbor2.CBORTag):
        return {"__cbor_tag__": obj.tag, "value": jsonable(obj.value, **kw)}
    if isinstance(obj, str):
        if truncate is not None and len(obj) > truncate:
            return obj[:truncate] + "..."
        return obj
    if isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    text = str(obj)
    if truncate is not None and len(text) > truncate:
        return text[:truncate] + "..."
    return text


# --- certificate decoding ---------------------------------------------------

def split_der(blob):
    """Split concatenated DER certificates by walking their SEQUENCE lengths."""
    out = []
    off = 0
    while off < len(blob):
        if blob[off] != 0x30:
            break
        first = blob[off + 1]
        if first & 0x80:
            count = first & 0x7F
            if count == 0 or off + 2 + count > len(blob):
                break
            length = int.from_bytes(blob[off + 2:off + 2 + count], "big")
            header = 2 + count
        else:
            length = first
            header = 2
        end = off + header + length
        if end > len(blob):
            break
        out.append(blob[off:end])
        off = end
    return out


def cert_name(name):
    """Prefer the CN; DICE certs often carry only a serialNumber."""
    try:
        cn = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn:
            return "CN=" + cn[0].value
        sn = name.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)
        if sn:
            value = sn[0].value
            short = value if len(value) <= 16 else value[:8] + ".." + value[-4:]
            return "SN=" + short
    except Exception:
        pass
    return name.rfc4514_string()[:40]


def key_brief(cert):
    try:
        key = cert.public_key()
    except Exception:
        return "?"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC " + key.curve.name
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA %d" % key.key_size
    return type(key).__name__


def cert_lines(blob, indent, *, label="certs"):
    """One essential line per certificate in a DER blob or list of DER blobs."""
    if x509 is None:
        return ["%s%s: install 'cryptography' to decode" % ("  " * indent,
                                                            label)]
    ders = split_der(blob) if isinstance(blob, bytes) else list(blob)
    certs = []
    for der in ders:
        try:
            certs.append(x509.load_der_x509_certificate(der))
        except Exception as exc:
            certs.append(exc)

    subjects = {}
    for i, cert in enumerate(certs):
        if not isinstance(cert, Exception):
            subjects.setdefault(cert.subject.rfc4514_string(), i)

    now = datetime.datetime.now(datetime.timezone.utc)
    lines = []
    pad = "  " * indent
    for i, cert in enumerate(certs):
        if isinstance(cert, Exception):
            lines.append("%s[%d] <unparsable: %s>" % (pad, i, cert))
            continue
        start = cert.not_valid_before_utc
        end = cert.not_valid_after_utc
        notes = []
        issuer = cert.issuer.rfc4514_string()
        if issuer == cert.subject.rfc4514_string():
            notes.append("self-signed")
        elif issuer in subjects:
            notes.append("issued by [%d]" % subjects[issuer])
        else:
            notes.append("issuer not in chain")
        if now < start:
            notes.append("NOT YET VALID")
        elif now > end:
            notes.append("EXPIRED")
        lines.append("%s[%d] %-24s %-10s %s..%s  %s" % (
            pad, i, cert_name(cert.subject), key_brief(cert),
            start.date(), end.date(), ", ".join(notes)))
    return lines


# --- SPDM signed_measurements summary ---------------------------------------

SPDM_CODE = {
    0x84: "GET_VERSION", 0x04: "VERSION",
    0xE1: "GET_CAPABILITIES", 0x61: "CAPABILITIES",
    0xE3: "NEGOTIATE_ALGORITHMS", 0x63: "ALGORITHMS",
    0x81: "GET_DIGESTS", 0x01: "DIGESTS",
    0x82: "GET_CERTIFICATE", 0x02: "CERTIFICATE",
    0x83: "CHALLENGE", 0x03: "CHALLENGE_AUTH",
    0xE0: "GET_MEASUREMENTS", 0x60: "MEASUREMENTS",
    0xFF: "RESPOND_IF_READY", 0x7F: "ERROR",
}
DMTF_MEAS_TYPE = {
    0: "immutable ROM", 1: "mutable firmware", 2: "hardware config",
    3: "firmware config", 4: "measurement manifest", 5: "device mode",
    6: "version", 7: "secure version number",
}


def spdm_msg_len(blob, off):
    """Length of the SPDM message at `off`, or None if the code is unknown."""
    version, code, param1 = blob[off], blob[off + 1], blob[off + 2]
    if code == 0x84:
        return 4
    if code == 0x04:
        return 6 + 2 * blob[off + 5]
    if code in (0xE1, 0x61):
        return 20 if version >= 0x12 else 12
    if code in (0xE3, 0x63):
        return int.from_bytes(blob[off + 4:off + 6], "little")
    if code == 0xE0:
        return 4 + (33 if param1 & 0x01 else 0)
    if code == 0x60:
        return len(blob) - off
    return None


def printable(raw):
    """Leading ASCII run of a raw value, if it looks like a label."""
    head = bytearray()
    for byte in raw:
        if 32 <= byte < 127:
            head.append(byte)
        else:
            break
    if len(head) < 4:
        return None
    tail = len(raw) - len(head)
    return head.decode("ascii"), tail


def measurement_blocks(record, indent, width, *, meas_cbor=False):
    """One line per SPDM measurement block in a measurement record."""
    lines = []
    pad = "  " * indent
    off = 0
    while off + 4 <= len(record):
        index, spec = record[off], record[off + 1]
        size = int.from_bytes(record[off + 2:off + 4], "little")
        value = record[off + 4:off + 4 + size]
        if size == 0 or len(value) != size:
            lines.append("%s<truncated block at +%d>" % (pad, off))
            break
        if spec == 0x01 and len(value) >= 3:  # DMTF measurement value
            kind = value[0]
            vsize = int.from_bytes(value[1:3], "little")
            body = value[3:3 + vsize]
            name = DMTF_MEAS_TYPE.get(kind & 0x7F, "type %d" % (kind & 0x7F))
            form = "raw" if kind & 0x80 else "digest"
            detail = ""
            text = printable(body) if kind & 0x80 else None
            inner = nested_cbor(body.lstrip(b"\xd9\xd9\xf7")) if kind & 0x80 \
                else None
            if text:
                detail = '"%s"' % brief_str(text[0], width)
                if text[1]:
                    detail += " + %d B" % text[1]
            elif inner is not None:
                tags = []
                node = inner
                while isinstance(node, cbor2.CBORTag):
                    tags.append("Tag(%d) %s" % (
                        node.tag, CBOR_TAG_NAME.get(node.tag, "?")))
                    node = node.value
                detail = "CBOR %s" % " / ".join(tags) if tags else "CBOR"
            else:
                detail = brief_bytes(body, width)
            lines.append("%s[%3d] %-22s %-6s %4d B  %s" % (
                pad, index, name, form, vsize, detail))
            if meas_cbor and inner is not None:
                dump_measurement_cbor(lines, inner, indent + 1, width)
        else:
            lines.append("%s[%3d] spec 0x%02x %d B  %s" % (
                pad, index, spec, size, brief_bytes(value, width)))
        off += 4 + size
    return lines


def measurements_lines(blob, indent, width, *, blocks=True,
                       meas_cbor=False):
    """Summarise an SPDM transcript ending in a MEASUREMENTS response."""
    pad = "  " * indent
    lines = []
    seen = []
    off = 0
    meas = None
    while off + 4 <= len(blob):
        version, code = blob[off], blob[off + 1]
        size = spdm_msg_len(blob, off)
        name = SPDM_CODE.get(code, "0x%02X" % code)
        seen.append(name)
        if size is None or size <= 0 or off + size > len(blob):
            lines.append("%s<stopped at +%d: %s>" % (pad, off, name))
            break
        if code == 0x60:
            meas = (version, off, size)
            break
        off += size

    if seen:
        wrapped = []
        line = ""
        for name in seen:
            piece = (", " if line else "") + name
            if len(line) + len(piece) > 58:
                wrapped.append(line)
                line = name
            else:
                line += piece
        wrapped.append(line)
        emit(lines, indent, "SPDM transcript", wrapped[0])
        pad_col = len("  " * indent) + max(8, 26 - 2 * indent) + 1
        for extra in wrapped[1:]:
            lines.append(" " * pad_col + extra)

    if meas is None:
        return lines

    version, off, size = meas
    body = blob[off:off + size]
    count = body[4]
    record_len = int.from_bytes(body[5:8], "little")
    record = body[8:8 + record_len]
    rest = body[8 + record_len:]
    nonce, opaque_len = rest[:32], int.from_bytes(rest[32:34], "little")
    signature = rest[34 + opaque_len:]
    emit(lines, indent, "MEASUREMENTS",
         "SPDM %d.%d, slot %d, %d block(s), record %d B" % (
             version >> 4, version & 0x0F, body[3] & 0x0F, count, record_len))
    if blocks:
        lines.extend(measurement_blocks(record, indent + 1, width,
                                        meas_cbor=meas_cbor))
    emit(lines, indent + 1, "nonce", brief_bytes(nonce, width))
    emit(lines, indent + 1, "opaque", "%d B" % opaque_len)
    emit(lines, indent + 1, "signature", "%d B" % len(signature))
    return lines


# --- concise tree dump ------------------------------------------------------

BYTES_ENC = "hex"          # set from --bytes; "hex" or "base64"


def encode_bytes(raw):
    """Render bytes in the format selected by --bytes."""
    if BYTES_ENC == "base64":
        return base64.b64encode(raw).decode()
    return raw.hex()


def brief_bytes(raw, width):
    """One-line preview of a byte string: encoded head plus its true size."""
    text = encode_bytes(raw)
    if len(text) > width:
        text = text[:width] + "..."
    out = "%s (%d B)" % (text, len(raw))
    # OIDs and labels are carried as ASCII bytes; show them as such
    if 4 <= len(raw) <= 64 and all(32 <= b < 127 for b in raw):
        out += ' "%s"' % raw.decode("ascii")
    return out


def brief_str(text, width):
    return text if len(text) <= width else text[:width] + "..."


def label_for(key, table):
    name = table.get(key)
    return "%s (%s)" % (key, name) if name else str(key)


def emit(out, indent, key, value=None):
    pad = "  " * indent
    if value is None:
        out.append("%s%s" % (pad, key))
    else:
        # keep the value column aligned across indent levels
        col = max(8, 26 - 2 * indent)
        out.append("%s%-*s %s" % (pad, col, key + ":", value))


def scalar(value, width, *, alg_table=None):
    """Render a leaf as a single short string, or None if it is not a leaf."""
    if isinstance(value, bytes):
        return brief_bytes(value, width)
    if isinstance(value, str):
        return '"%s"' % brief_str(value, width)
    if isinstance(value, bool) or value is None:
        return str(value)
    if isinstance(value, int):
        name = (alg_table or {}).get(value)
        return "%d (%s)" % (value, name) if name else str(value)
    if isinstance(value, float):
        return repr(value)
    return None


def join_path(prefix, label):
    return "%s > %s" % (prefix, label) if prefix else label


def tag_label(tag):
    name = CBOR_TAG_NAME.get(tag.tag)
    return "Tag(%d)%s" % (tag.tag, " " + name if name else "")


def dump_generic(out, obj, indent, width, *, table=None, alg_table=None,
                 prefix=""):
    """Fallback renderer for structures the EAT walker does not recognise.

    Containers holding a single child are folded into one `a > b > c` path so
    deeply wrapped structures (CoMID and friends) do not cost a line per level.
    """
    leaf = scalar(obj, width, alg_table=alg_table)
    if leaf is not None:
        emit(out, indent, prefix, leaf) if prefix else emit(out, indent, leaf)
        return

    if isinstance(obj, cbor2.CBORTag):
        label = join_path(prefix, tag_label(obj))
        inner = scalar(obj.value, width)
        if inner is not None:
            emit(out, indent, label, inner)
        else:
            dump_generic(out, obj.value, indent, width, prefix=label)
        return

    if isinstance(obj, collections.abc.Mapping):
        items = list(obj.items())
        if len(items) == 1:
            key, value = items[0]
            name = label_for(key, table or {}) if isinstance(key, int) \
                else str(key)
            dump_generic(out, value, indent, width,
                         prefix=join_path(prefix, name))
            return
        if prefix:
            emit(out, indent, prefix)
            indent += 1
        for key, value in items:
            name = label_for(key, table or {}) if isinstance(key, int) \
                else str(key)
            leaf = scalar(value, width)
            if leaf is not None:
                emit(out, indent, name, leaf)
            else:
                dump_generic(out, value, indent, width, prefix=name)
        return

    if isinstance(obj, (list, tuple, set, frozenset)):
        items = list(obj)
        leaves = [scalar(v, width) for v in items]
        if leaves and all(x is not None for x in leaves):
            if len(leaves) <= 4:
                inline = "[%s]" % ", ".join(leaves)
                emit(out, indent, prefix, inline) if prefix \
                    else emit(out, indent, inline)
                return
            if len(set(leaves)) == 1:
                inline = "%d x %s" % (len(leaves), leaves[0])
                emit(out, indent, prefix, inline) if prefix \
                    else emit(out, indent, inline)
                return
            if max(len(x) for x in leaves) <= 12:
                if prefix:
                    emit(out, indent, prefix)
                    indent += 1
                line = ""
                for leaf in leaves:
                    piece = (", " if line else "") + leaf
                    if len(line) + len(piece) > 60:
                        emit(out, indent, line)
                        line = leaf
                    else:
                        line += piece
                if line:
                    emit(out, indent, line)
                return
        if len(items) == 1:
            dump_generic(out, items[0], indent, width,
                         prefix=join_path(prefix, "[0]"))
            return
        if prefix:
            emit(out, indent, prefix)
            indent += 1
        i = 0
        while i < len(items):
            leaf = leaves[i]
            if leaf is None:
                dump_generic(out, items[i], indent, width, prefix="[%d]" % i)
                i += 1
                continue
            # collapse runs of identical entries (mostly unused all-zero slots)
            run = i + 1
            while run < len(items) and leaves[run] == leaf:
                run += 1
            if run - i >= 3:
                emit(out, indent, "[%d..%d]" % (i, run - 1),
                     "%d x %s" % (run - i, leaf))
            else:
                for j in range(i, run):
                    emit(out, indent, "[%d]" % j, leaf)
            i = run
        return
    emit(out, indent, str(obj))


def section_inline(out, indent, title, section, width, table, skip_keys=()):
    """Print a one-entry COSE header section on a single line."""
    if not isinstance(section, collections.abc.Mapping) or len(section) != 1:
        return False
    (key, value), = section.items()
    if key in skip_keys:
        return False
    leaf = scalar(value, width,
                  alg_table=COSE_ALG if key == 1 else None)
    if leaf is None:
        return False
    name = label_for(key, table) if isinstance(key, int) else str(key)
    emit(out, indent, title, "%s = %s" % (name, leaf))
    return True


def dump_sign1(out, sign1, indent, width, *, decode_certs=False,
               meas_cbor=False):
    """Render a COSE_Sign1 [protected, unprotected, payload, signature]."""
    try:
        protected, unprotected, payload, signature = sign1
    except (TypeError, ValueError):
        dump_generic(out, sign1, indent, width)
        return

    prot = nested_cbor(protected) if isinstance(protected, bytes) else protected
    if section_inline(out, indent, "protected", prot, width, COSE_HDR):
        pass
    elif isinstance(prot, collections.abc.Mapping):
        emit(out, indent, "protected")
        for key, value in prot.items():
            name = label_for(key, COSE_HDR)
            if key == 1:
                emit(out, indent + 1, name, scalar(value, width,
                                                   alg_table=COSE_ALG))
            elif key == 34 and isinstance(value, (list, tuple)) \
                    and len(value) == 2:
                emit(out, indent + 1, name, "%s %s" % (
                    scalar(value[0], width, alg_table=COSE_HASH),
                    brief_bytes(value[1], width)
                    if isinstance(value[1], bytes) else value[1]))
            else:
                leaf = scalar(value, width)
                if leaf is not None:
                    emit(out, indent + 1, name, leaf)
                else:
                    dump_generic(out, value, indent + 1, width, prefix=name)
    else:
        emit(out, indent, "protected")
        dump_generic(out, prot, indent + 1, width)

    if section_inline(out, indent, "unprotected", unprotected, width,
                      COSE_HDR, skip_keys=(32, 33)):
        pass
    elif isinstance(unprotected, collections.abc.Mapping) and unprotected:
        emit(out, indent, "unprotected")
        for key, value in unprotected.items():
            name = label_for(key, COSE_HDR) if isinstance(key, int) else str(key)
            if key in (32, 33) and isinstance(value, (list, tuple)):
                emit(out, indent + 1, name, "%d cert(s), %s bytes" % (
                    len(value), ", ".join(str(len(c)) for c in value)))
                if decode_certs:
                    out.extend(cert_lines(value, indent + 2))
            else:
                leaf = scalar(value, width)
                if leaf is not None:
                    emit(out, indent + 1, name, leaf)
                else:
                    dump_generic(out, value, indent + 1, width, prefix=name)
    else:
        emit(out, indent, "unprotected", "(empty)")

    claims = nested_cbor(payload) if isinstance(payload, bytes) else payload
    emit(out, indent, "claims")
    if isinstance(claims, collections.abc.Mapping):
        dump_claims(out, claims, indent + 1, width, meas_cbor=meas_cbor)
    else:
        dump_generic(out, claims, indent + 1, width)

    if isinstance(signature, bytes):
        emit(out, indent, "signature", "%d B" % len(signature))


def dump_claims(out, claims, indent, width, *, meas_cbor=False):
    for key, value in claims.items():
        name = label_for(key, CWT_CLAIM) if isinstance(key, int) else str(key)
        if key == 266 and isinstance(value, collections.abc.Mapping):
            emit(out, indent, name)
            for sub, digest in value.items():
                if isinstance(digest, (list, tuple)) and len(digest) == 2:
                    emit(out, indent + 1, str(sub), "%s %s" % (
                        scalar(digest[0], width, alg_table=COSE_HASH),
                        brief_bytes(digest[1], width)
                        if isinstance(digest[1], bytes) else digest[1]))
                else:
                    emit(out, indent + 1, str(sub) + ":")
                    dump_generic(out, digest, indent + 2, width)
            continue
        if key == 273 and isinstance(value, (list, tuple)):
            emit(out, indent, name)
            for entry in value:
                if isinstance(entry, (list, tuple)) and len(entry) == 2:
                    fmt = CONTENT_FORMAT.get(entry[0], entry[0])
                    body = entry[1]
                    emit(out, indent + 1, str(fmt),
                         brief_bytes(body, width)
                         if isinstance(body, bytes) else str(body))
                    inner = nested_cbor(body) if (meas_cbor
                                                  and isinstance(body, bytes)) \
                        else None
                    if inner is not None:
                        dump_measurement_cbor(out, inner, indent + 2, width)
                else:
                    dump_generic(out, entry, indent + 1, width)
            continue
        leaf = scalar(value, width)
        if leaf is not None:
            emit(out, indent, name, leaf)
        else:
            dump_generic(out, value, indent, width, prefix=name)


def dump_measurement_cbor(out, obj, indent, width):
    """Render CBOR carried inside a measurement body.

    A nested CWT/COSE_Sign1 is shown with the same COSE/claim labels as the
    outer token; anything else falls back to the generic dumper.
    """
    node = obj
    tags = []
    while isinstance(node, cbor2.CBORTag):
        tags.append("Tag(%d) %s" % (node.tag, CBOR_TAG_NAME.get(node.tag, "?")))
        node = node.value
    if tags and isinstance(node, (list, tuple)) and len(node) == 4:
        # the parent line already names the tag chain
        dump_sign1(out, node, indent, width, meas_cbor=True)
        return
    if tags:
        emit(out, indent, " / ".join(tags))
        indent += 1
    if isinstance(node, collections.abc.Mapping):
        dump_generic(out, node, indent, width)
        return
    dump_generic(out, node, indent, width)


def dump_tree(decoded, *, width=64, decode_certs=False,
              decode_measurements=False, meas_cbor=False):
    """Render the bundle as a short annotated tree instead of raw JSON."""
    out = []
    obj = decoded
    if isinstance(obj, cbor2.CBORTag) and obj.tag == DETACHED_BUNDLE_TAG:
        emit(out, 0, "Tag(%d) Detached EAT Bundle" % obj.tag)
        try:
            main, detached = obj.value[0], obj.value[1]
        except (TypeError, IndexError):
            dump_generic(out, obj.value, 1, width)
            return "\n".join(out)

        token = nested_cbor(main) if isinstance(main, bytes) else main
        chain = []
        while isinstance(token, cbor2.CBORTag):
            chain.append("Tag(%d) %s" % (
                token.tag, CBOR_TAG_NAME.get(token.tag, "?")))
            token = token.value
        emit(out, 1, "main token" + (" [%s]" % " / ".join(chain) if chain
                                     else ""))
        dump_sign1(out, token, 2, width, decode_certs=decode_certs,
                   meas_cbor=meas_cbor)

        emit(out, 1, "detached parts")
        if isinstance(detached, collections.abc.Mapping):
            for name, blob in detached.items():
                emit(out, 2, str(name), "%d B" % len(blob)
                     if isinstance(blob, bytes) else "")
                inner = nested_cbor(blob) if isinstance(blob, bytes) else blob
                if isinstance(inner, collections.abc.Mapping):
                    for key, value in inner.items():
                        is_chain = (isinstance(value, bytes)
                                    and "cert" in str(key).lower())
                        detail = "%d B" % len(value) \
                            if isinstance(value, bytes) \
                            else scalar(value, width) or ""
                        if is_chain and decode_certs and x509 is not None:
                            detail += ", %d cert(s)" % len(split_der(value))
                        emit(out, 3, str(key), detail)
                        if is_chain and decode_certs:
                            out.extend(cert_lines(value, 4))
                        if (decode_measurements and isinstance(value, bytes)
                                and "measurement" in str(key).lower()):
                            try:
                                out.extend(measurements_lines(
                                    value, 4, width, meas_cbor=meas_cbor))
                            except (IndexError, ValueError) as exc:
                                emit(out, 4, "<unparsable: %s>" % exc)
                elif inner is not None:
                    dump_generic(out, inner, 3, width)
        else:
            dump_generic(out, detached, 2, width)
        return "\n".join(out)

    dump_generic(out, obj, 0, width)
    return "\n".join(out)


EAT_NONCE_CLAIM = 10
EAT_PROFILE_CLAIM = 265
EAT_SUBMODS_CLAIM = 266
DETACHED_BUNDLE_TAG = 602
CWT_TAG = 61


def eat_claims(decoded):
    """Best-effort walk to the claims map of a detached EAT bundle.

    Layout (RFC 9711): Tag(602, [ main-token bstr, { name => detached bstr } ])
    where main-token is Tag(61, Tag(18, COSE_Sign1)) and the Sign1 payload
    is the claims map.
    """
    try:
        if not (isinstance(decoded, cbor2.CBORTag)
                and decoded.tag == DETACHED_BUNDLE_TAG):
            return None, {}
        main, detached = decoded.value[0], decoded.value[1]
        token = cbor2.loads(main) if isinstance(main, bytes) else main
        while isinstance(token, cbor2.CBORTag):
            token = token.value
        payload = token[2]
        claims = cbor2.loads(payload) if isinstance(payload, bytes) else payload
        return claims, detached
    except Exception:
        return None, {}


def show_eat_summary(decoded, nonce_b64, quiet=False):
    claims, detached = eat_claims(decoded)
    if claims is None:
        return
    profile = claims.get(EAT_PROFILE_CLAIM)
    if profile:
        log("  Profile        : %s" % profile, quiet=quiet)
    echoed = claims.get(EAT_NONCE_CLAIM)
    if isinstance(echoed, bytes):
        match = base64.b64encode(echoed).decode() == nonce_b64
        log("  Nonce (token)  : %s" % encode_bytes(echoed), quiet=quiet)
        log("  Nonce echo     : %s" % ("match" if match else "MISMATCH"),
            quiet=quiet)
        if not match:
            log("  Nonce (sent)   : %s"
                % encode_bytes(base64.b64decode(nonce_b64)), quiet=quiet)
    submods = claims.get(EAT_SUBMODS_CLAIM) or {}
    if submods:
        log("  Submodules     : %s" % ", ".join(str(k) for k in submods),
            quiet=quiet)
    if detached:
        log("  Detached parts : %s" % ", ".join(str(k) for k in detached),
            quiet=quiet)


def wait_for_state(client, states, *, interval, timeout, quiet=False,
                   label="state"):
    """Poll the bundle resource until its status is in `states`."""
    deadline = time.monotonic() + timeout
    while True:
        body = client.get(BUNDLE_PATH)
        status = normalize(bundle_status(body))
        log("  Status         : %s" % (status or "-"), quiet=quiet)
        if status in states:
            return body, status
        if status not in BUSY_STATES:
            raise RedfishError(f"unexpected {label} '{status}' from {BUNDLE_PATH}")
        if time.monotonic() >= deadline:
            raise RedfishError(f"timed out waiting for {label} in {states}")
        time.sleep(interval)


def step_pause(args, what):
    """Pause between steps so the exchange is easy to follow on the wire."""
    if args.step_delay > 0:
        log("  ... pausing %gs before %s" % (args.step_delay, what),
            quiet=args.quiet)
        time.sleep(args.step_delay)


def run_once(client, args, iteration):
    quiet = args.quiet
    log("\n=== Iteration %d/%d ===" % (iteration, args.loop), quiet=quiet)

    log("[1] GET %s" % COLLECTION_PATH, quiet=quiet)
    show_collection(client.get(COLLECTION_PATH), quiet=quiet)

    step_pause(args, "step 2")
    log("[2] GET %s" % BUNDLE_PATH, quiet=quiet)
    body, _ = wait_for_state(
        client, READY_STATES + IDLE_STATES,
        interval=args.interval, timeout=args.timeout, quiet=quiet,
        label="pre-request status",
    )
    show_bundle_resource(body, quiet=quiet)

    step_pause(args, "step 3")
    nonce = base64.b64encode(secrets.token_bytes(32)).decode()
    log("[3] POST %s" % ACTION_PATH, quiet=quiet)
    log("  Nonce          : %s" % nonce, quiet=quiet)
    if BYTES_ENC != "base64":
        log("  Nonce (hex)    : %s" % base64.b64decode(nonce).hex(),
            quiet=quiet)
    resp = client.post(ACTION_PATH, {"Nonce": nonce})
    if resp:
        log("  Response       : %s" % json.dumps(resp)[:400], quiet=quiet)

    step_pause(args, "step 4")
    log("[4] GET %s (poll)" % BUNDLE_PATH, quiet=quiet)
    body, _ = wait_for_state(
        client, READY_STATES,
        interval=args.interval, timeout=args.timeout, quiet=quiet,
        label="bundle status",
    )
    show_bundle_resource(body, quiet=quiet)

    encoded = bundle_blob(body)
    if not encoded:
        raise RedfishError(
            "status is Ready but no bundle property was returned; keys: %s"
            % ", ".join(sorted(body))
        )

    raw, decoded = decode_bundle(encoded)
    log("  Bundle bytes   : %d (after base64 decode)" % len(raw), quiet=quiet)
    show_eat_summary(decoded, nonce, quiet=quiet)
    if args.show_cbor:
        step_pause(args, "the decoded bundle")
        print("--- Decoded Bundle (CBOR) ---")
        if args.format == "json":
            print(json.dumps(jsonable(decoded, recurse=not args.no_recurse,
                                      truncate=args.truncate),
                             indent=2, sort_keys=True))
        else:
            default_width = 64 if args.bytes_enc == "hex" else 48
            print(dump_tree(decoded, width=args.truncate or default_width,
                            decode_certs=args.decode_certs,
                            decode_measurements=args.decode_measurements,
                            meas_cbor=args.meas_cbor))

    if args.save_bundle:
        path = args.save_bundle
        if args.loop > 1:
            root, ext = os.path.splitext(path)
            path = f"{root}_{iteration}{ext or '.cbor'}"
        with open(path, "wb") as fh:
            fh.write(raw)
        log("  Saved raw CBOR : %s" % path, quiet=quiet)

    return decoded


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Request and decode an OpenBMC Composite EAT bundle "
                    "over Redfish.",
    )
    parser.add_argument("-H", "--host", required=True,
                        help="BMC hostname or IP address")
    parser.add_argument("-P", "--port", type=int, default=None,
                        help="TCP port (default: scheme default)")
    parser.add_argument("-u", "--user", default=os.environ.get("BMC_USER", "root"),
                        help="Redfish user name (env BMC_USER)")
    parser.add_argument("-p", "--password",
                        default=os.environ.get("BMC_PASSWORD", "0penBmc"),
                        help="Redfish password (env BMC_PASSWORD)")
    parser.add_argument("-n", "--loop", type=int, default=1,
                        help="number of times to run the whole sequence")
    parser.add_argument("--scheme", choices=("https", "http"), default="https",
                        help="URL scheme (default: https)")
    parser.add_argument("--verify", action="store_true",
                        help="verify the TLS certificate (default: off)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="poll interval in seconds (default: 2)")
    parser.add_argument("--step-delay", type=float, default=5.0,
                        help="pause in seconds between steps, and before the "
                             "decoded bundle is printed (default: 5)")
    parser.add_argument("--loop-delay", type=float, default=10.0,
                        help="pause in seconds between iterations "
                             "(default: 10)")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="max seconds to wait for a state change")
    parser.add_argument("--http-timeout", type=float, default=30.0,
                        help="per-request HTTP timeout in seconds")
    parser.add_argument("--show-cbor", dest="show_cbor",
                        action="store_true", default=True,
                        help="print the decoded CBOR bundle (default)")
    parser.add_argument("--no-cbor", dest="show_cbor", action="store_false",
                        help="skip the decoded CBOR dump; still fetch, decode "
                             "and check the bundle")
    parser.add_argument("--decode-certs", action="store_true",
                        help="decode the X.509 certificates in cert_chain and "
                             "x5chain, showing one summary line each "
                             "(requires the 'cryptography' module)")
    parser.add_argument("--decode-measurements", action="store_true",
                        help="summarise each detached signed_measurements blob "
                             "(SPDM transcript, measurement blocks, nonce and "
                             "signature sizes)")
    parser.add_argument("--decode-measurement-cbor", dest="meas_cbor",
                        action="store_true",
                        help="dump the CBOR carried inside measurements: the "
                             "EAT measurements claim (273) and any SPDM "
                             "measurement block whose raw value is CBOR")
    parser.add_argument("--bytes", dest="bytes_enc",
                        choices=("hex", "base64"), default="hex",
                        help="how byte strings (nonces, digests, signatures) "
                             "are shown in the decoded output (default: hex)")
    parser.add_argument("--format", choices=("tree", "json"), default="tree",
                        help="decoded bundle layout: a concise annotated tree "
                             "(default) or the full JSON structure")
    parser.add_argument("--truncate", nargs="?", type=int, const=128,
                        default=None, metavar="N",
                        help="shorten every field in the decoded CBOR to the "
                             "first N bytes/characters and append '...'; with "
                             "--format tree it sets the preview width "
                             "(N defaults to 128 when the flag is given "
                             "without a value)")
    parser.add_argument("--no-recurse", action="store_true",
                        help="do not decode CBOR nested inside byte strings")
    parser.add_argument("--save-bundle", metavar="FILE",
                        help="write the raw CBOR bundle to FILE")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only print the decoded bundle")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.loop < 1:
        print("error: --loop must be >= 1", file=sys.stderr)
        return 2

    global BYTES_ENC
    BYTES_ENC = args.bytes_enc

    client = RedfishClient(
        args.host, args.user, args.password,
        scheme=args.scheme, port=args.port,
        verify=args.verify, timeout=args.http_timeout,
    )

    failures = 0
    for iteration in range(1, args.loop + 1):
        try:
            run_once(client, args, iteration)
        except (RedfishError, requests.RequestException,
                cbor2.CBORDecodeError, ValueError) as exc:
            failures += 1
            print("iteration %d failed: %s" % (iteration, exc), file=sys.stderr)
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return 130

        # Pause before looping back to step 1; nothing to wait for after the
        # last iteration.
        if iteration < args.loop and args.loop_delay > 0:
            log("\n[5] Sleeping %gs before iteration %d"
                % (args.loop_delay, iteration + 1), quiet=args.quiet)
            try:
                time.sleep(args.loop_delay)
            except KeyboardInterrupt:
                print("\ninterrupted", file=sys.stderr)
                return 130

    if failures:
        print("\n%d/%d iteration(s) failed" % (failures, args.loop),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
