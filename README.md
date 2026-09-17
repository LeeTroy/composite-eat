# Composite EAT Bundle Client

A small CLI that walks the OpenBMC Redfish flow for retrieving a **Composite
EAT (Entity Attestation Token) bundle**, then base64- and CBOR-decodes the
result.

## What it does

Each iteration performs:

1. `GET /redfish/v1/ComponentIntegrity/` — show the collection members.
2. `GET /redfish/v1/ComponentIntegrity/Oem/OpenBMC/CompositeEATBundle/` —
   continue once the status is `Ready` or `Idle` (polls while `InProgress`).
3. `POST /redfish/v1/ComponentIntegrity/Actions/Oem/OpenBMC.GetCompositeEATBundle`
   with a freshly generated nonce:

   ```json
   { "Nonce": "<base64 of 32 random bytes>" }
   ```

4. `GET .../CompositeEATBundle/` in a loop — sleep 2 s while `InProgress`;
   when `Ready`, base64-decode the `CompositeEATBundle` property, parse it as
   CBOR and print it.
5. Pause `--loop-delay` seconds (default 10), then go back to step 1 until
   `--loop` iterations have run. The pause is skipped after the last one.

There is also a `--step-delay` pause (default 5 s) before steps 2, 3 and 4,
and between the step 4 summary and the decoded bundle dump.

Byte strings — nonces, digests, signatures, UEID — are shown as hex by
default; `--bytes base64` switches them back to base64. The nonce echo check
prints the token's nonce in the selected encoding, and step 3 adds a
`Nonce (hex)` line next to the base64 value actually sent on the wire, so the
two are directly comparable. Because hex needs twice the characters, the tree
preview width defaults to 64 instead of 48 so a 32-byte nonce still fits on
one line.

`--format tree` (the default) prints a short annotated tree: COSE header
parameters, CWT/EAT claims, COSE algorithm and hash identifiers are shown by
name, byte strings as a preview plus their true length, and the cert
chain and detached parts as sizes. It is ~1 KB versus ~22 KB for the JSON
form. `--truncate N` sets the preview width here.

`--decode-certs` parses the DER certificates in the token's `x5chain` header
and in each detached part's `cert_chain`, printing one line per certificate:
subject CN (or a shortened serialNumber for DICE certs that have no CN), key
type and curve, validity dates, and how it links to the rest of the chain
(`self-signed`, `issued by [n]`, or `issuer not in chain`), plus `EXPIRED` /
`NOT YET VALID` when the validity window does not cover now. It needs the
`cryptography` module; without it the script still runs and says so. This is
a readability aid, not chain validation — no signature or path checking is
performed.

```
      33 (x5chain):        4 cert(s), 1465, 770, 909, 675 bytes
        [0] CN=DPE Leaf              EC secp384r1 2023-01-01..9999-12-31  issued by [1]
        [1] CN=Caliptra 1.0 Rt Alias EC secp384r1 2023-01-01..9999-12-31  issued by [2]
...
      cert_chain:          4983 B, 6 cert(s)
        [0] CN=DevelopCA             EC secp384r1 2026-09-08..2036-09-05  self-signed
        [1] CN=Caliptra 2.1 Ecc384 IDevID EC secp384r1 2026-09-08..2027-09-08  issued by [0]
```

`--decode-measurements` summarises each detached `signed_measurements` blob.
These are SPDM message transcripts: the exchange is listed by message name,
then the trailing `MEASUREMENTS` response is broken out into its measurement
blocks (index, DMTF value type, digest/raw form, size and a preview), nonce,
opaque data and signature sizes. A raw block whose value is itself CBOR is
identified rather than dumped.

```
      signed_measurements: 375 B
        SPDM transcript:   GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES
                           NEGOTIATE_ALGORITHMS, ALGORITHMS, GET_MEASUREMENTS
                           MEASUREMENTS
        MEASUREMENTS:      SPDM 1.2, slot 0, 2 block(s), record 78 B
          [  1] mutable firmware       digest   48 B  AQEBAQEBAQEBAQEB... (48 B)
          [ 26] type 9                 raw      16 B  "0123456789ab" + 4 B
          [253] type 10                raw     395 B  CBOR Tag(61) CWT / Tag(18) COSE_Sign1
            protected:     1 (alg) = -35 (ES384)
            unprotected:   4 (kid) = 4e1060f07274aeb56409503f163531aa473a7eb1... (48 B)
            claims
              10 (nonce):  3277029318b0de1b9501761c9232ab946a1c122ae7b1e1d73e151e82c121f842
              263 (dbgstat): 1
              265 (profile) > Tag(111): 312e332e...312e33 (21 B) "1.3.6.1.4.1.42623.1.3"
              273 (measurements)
                10571:     a100a1008182a100a300d902304e706c6174666f726d2d73... (116 B)
                  0 > 0 > [0]
                    [0] > 0
                      0 > Tag(560): 706c6174666f726d2d7374617465 (14 B) "platform-state"
                      1:       "Aspeed Technology"
                      2:       "AST1040"
                    [1] > [0]
                      0:       0
                      1 > 2 > [0]: [7, 5f91f06163adf14215146e922ce9b1eb... (48 B)]
              1 (iss):     "CN=Caliptra EAT DPE Attestation Key"
            signature:     96 B
```

Three rules keep even this deep structure short: containers holding a single
child are folded into one `a > b > c` path line instead of a line per level
(CoMID nests heavily); runs of identical array entries are collapsed
(`[4..30]: 27 x 0000...`), which matters for the measurement claim's 32
registers where most are unused; and byte strings that are entirely printable
ASCII get their text shown next to the hex. The full dump with every decoder
enabled is ~73 lines, ~26 with none.

Like `--decode-certs`, this is decoding for readability — the SPDM signature
is not verified.

`--format json` gives the full structure instead, with every byte string
in base64. There, `--truncate N` cuts each leaf to the first N bytes
(default 128 when passed bare), appends `...`, and adds a `__bytes_len__`
field with the original length — ~4.3 KB at 128, ~3.3 KB at 32.

`--no-cbor` suppresses the (large) decoded dump while still fetching,
decoding and nonce-checking the bundle — useful for long soak runs, where
`--save-bundle` can keep the raw bytes for later inspection.

Only the essential response fields are printed (name, member list, id, status,
nonce, bundle size) plus the decoded bundle.

The bundle is an RFC 9711 **Detached EAT Bundle** — `Tag(602, [main-token,
{name => detached-claims}])` where the main token is `Tag(61, Tag(18,
COSE_Sign1))`. Byte strings that themselves contain CBOR (the COSE headers,
the claims payload, each detached part) are unwrapped recursively so the
output shows real claims instead of one opaque blob; `--no-recurse` turns that
off. The script also checks that the EAT nonce claim (10) in the signed token
matches the nonce it sent: it prints the nonce carried in the token
(`Nonce (token)`) and the verdict `Nonce echo: match` / `MISMATCH`. On a
mismatch the nonce that was sent is printed too, so both values are visible.

Note: this script does **not** verify the COSE signature or the certificate
chain — it only retrieves, decodes and checks nonce freshness.

## Setup (venv)

```bash
cd /home/troylee/Workspaces/AST2700/composite-eat
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python composite_eat.py -H 192.168.0.100 -u root -p 0penBmc -n 5
```

### Options

| Option | Default | Description |
| --- | --- | --- |
| `-H, --host` | *(required)* | BMC hostname or IP |
| `-P, --port` | scheme default | TCP port |
| `-u, --user` | `$BMC_USER` or `root` | Redfish user name |
| `-p, --password` | `$BMC_PASSWORD` or `0penBmc` | Redfish password |
| `-n, --loop` | `1` | How many times to run the whole sequence |
| `--scheme` | `https` | `https` or `http` |
| `--verify` | off | Verify the TLS certificate (self-signed BMC certs fail) |
| `--interval` | `2.0` | Poll interval in seconds |
| `--step-delay` | `5.0` | Pause between steps and before printing the decoded bundle (`0` disables) |
| `--loop-delay` | `10.0` | Pause between iterations, in seconds (`0` disables) |
| `--timeout` | `120.0` | Max seconds to wait for a state change |
| `--http-timeout` | `30.0` | Per-request HTTP timeout |
| `--show-cbor` / `--no-cbor` | show | Print or suppress the decoded CBOR dump (the bundle is still fetched, decoded and nonce-checked either way) |
| `--decode-measurement-cbor` | off | Dump the CBOR carried inside measurements |
| `--decode-measurements` | off | Summarise each detached `signed_measurements` blob |
| `--decode-certs` | off | Decode the X.509 certs in `cert_chain` / `x5chain` to one summary line each |
| `--bytes {hex,base64}` | `hex` | Encoding for byte strings (nonces, digests, signatures) in the decoded output |
| `--format {tree,json}` | `tree` | Concise annotated tree, or the full JSON structure |
| `--truncate [N]` | off (128 if bare) | Cap each decoded field at N bytes/chars and append `...` |
| `--no-recurse` | off | Do not decode CBOR nested inside byte strings |
| `--save-bundle FILE` | – | Write the raw CBOR bytes to `FILE` (suffixed with the iteration number when `--loop > 1`) |
| `-q, --quiet` | off | Print only the decoded bundle |

Credentials can be supplied through the environment instead of the command
line so they do not land in your shell history:

```bash
export BMC_USER=root
export BMC_PASSWORD='0penBmc'
python composite_eat.py -H 192.168.0.100 -n 3
```

### Example output

Against `ast2700-irot.local`:

```
./composite_eat.py -H ast2700-irot.local -u root -p 0penBmc -n 1000 --scheme https --truncate 64 --decode-certs --decode-measurements  --decode-measurement-cbor
=== Iteration 1/1000 ===
[1] GET /redfish/v1/ComponentIntegrity/
  Name           : Component Integrity Collection
  Members@count  : 2
  Member         : /redfish/v1/ComponentIntegrity/smc0
  Member         : /redfish/v1/ComponentIntegrity/smc1
  ... pausing 5s before step 2
[2] GET /redfish/v1/ComponentIntegrity/Oem/OpenBMC/CompositeEATBundle/
  Status         : ready
  Id             : CompositeEATBundle
  Status         : Ready
  Bundle length  : 23020 (base64 chars)
  ... pausing 5s before step 3
[3] POST /redfish/v1/ComponentIntegrity/Actions/Oem/OpenBMC.GetCompositeEATBundle
  Nonce          : i+1EEnZm5EsCEGIrLwQwtb7LJWtTNYWCGX028FteIFs=
  Nonce (hex)    : 8bed44127666e44b0210622b2f0430b5becb256b53358582197d36f05b5e205b
  ... pausing 5s before step 4
[4] GET /redfish/v1/ComponentIntegrity/Oem/OpenBMC/CompositeEATBundle/ (poll)
  Status         : ready
  Id             : CompositeEATBundle
  Status         : Ready
  Bundle length  : 23020 (base64 chars)
  Bundle bytes   : 17263 (after base64 decode)
  Profile        : https://github.com/aspeedtech-bmc/profile/composite_eat
  Nonce (token)  : 8bed44127666e44b0210622b2f0430b5becb256b53358582197d36f05b5e205b
  Nonce echo     : match
  Submodules     : env.smc0, env.smc1
  Detached parts : env.smc0, env.smc1
  ... pausing 5s before the decoded bundle
--- Decoded Bundle (CBOR) ---
Tag(602) Detached EAT Bundle
  main token [Tag(61) CWT / Tag(18) COSE_Sign1]
    protected
      1 (alg):             -35 (ES384)
      3 (content type):    "application/eat+cwt"
      34 (x5t):            -43 (SHA-384) 18770399228bed601d95e891f4fc6927faaa5c96437ab4d934ca3919a488b5fc... (48 B)
    unprotected
      33 (x5chain):        4 cert(s), 1465, 770, 909, 675 bytes
        [0] CN=DPE Leaf              EC secp384r1 2023-01-01..9999-12-31  issued by [1]
        [1] CN=Caliptra 1.0 Rt Alias EC secp384r1 2023-01-01..9999-12-31  issued by [2]
        [2] CN=Caliptra 1.0 FMC Alias EC secp384r1 2023-01-01..9999-12-31  issued by [3]
        [3] CN=Caliptra 1.0 LDevID   EC secp384r1 2023-01-01..9999-12-31  issuer not in chain
    claims
      10 (nonce):          8bed44127666e44b0210622b2f0430b5becb256b53358582197d36f05b5e205b (32 B)
      256 (ueid):          aa42300410323205 (8 B)
      265 (profile):       "https://github.com/aspeedtech-bmc/profile/composite_eat"
      266 (submods)
        env.smc0:          -43 (SHA-384) acbcbeeaa161d4659dba4f466d6adf8323f095db5364848564da54522fb975c9... (48 B)
        env.smc1:          -43 (SHA-384) 4423f259987f2765018210b786678a052f9878442426bb4045e92cfa385b1caf... (48 B)
      273 (measurements)
        application/cbor:  a50198205830b3f58c3bfc4318dd23ab2eba8e7d00ef2445c5d1783cd6a74c5b... (1824 B)
          1
            [0]:           b3f58c3bfc4318dd23ab2eba8e7d00ef2445c5d1783cd6a74c5b1246ee54d26c... (48 B)
            [1]:           b3f58c3bfc4318dd23ab2eba8e7d00ef2445c5d1783cd6a74c5b1246ee54d26c... (48 B)
            [2]:           97b1dc9fce4b7b3495abcaa9fc663828fefdf51beddc200192ad434c7b5be3c7... (48 B)
            [3]:           97b1dc9fce4b7b3495abcaa9fc663828fefdf51beddc200192ad434c7b5be3c7... (48 B)
            [4..30]:       27 x 0000000000000000000000000000000000000000000000000000000000000000... (48 B)
            [31]:          c9ee4ded92eba1613836a5c05e188989c11526c81d6129f744cfe27df5ce7460... (48 B)
          2:               32 x 0
          3:               0000000000000000000000000000000000000000000000000000000000000000 (32 B)
          4:               bcbd7ea3efcd64df89250caede863dd1c03b24513513fd8e80911a878ae598d0... (48 B)
          5:               704e9517519d526de2d6c66ea415898968f71d8df37dc63ea53a779d46e89590... (96 B)
    signature:             96 B
  detached parts
    env.smc0:              5396 B
      cert_chain:          4983 B, 6 cert(s)
        [0] CN=DevelopCA             EC secp384r1 2026-09-08..2036-09-05  self-signed
        [1] CN=Caliptra 2.1 Ecc384 IDevID EC secp384r1 2026-09-08..2027-09-08  issued by [0]
        [2] CN=Caliptra 2.1 Ecc384 LDevID EC secp384r1 2023-01-01..9999-12-31  issued by [1]
        [3] CN=Caliptra 2.1 Ecc384 FMC Alias EC secp384r1 2023-01-01..9999-12-31  issued by [2]
        [4] CN=Caliptra 2.1 Ecc384 Rt Alias EC secp384r1 2023-01-01..9999-12-31  issued by [3]
        [5] CN=DPE Leaf              EC secp384r1 2023-01-01..9999-12-31  issued by [4]
      signed_measurements: 375 B
        SPDM transcript:   GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES
                           NEGOTIATE_ALGORITHMS, ALGORITHMS, GET_MEASUREMENTS
                           MEASUREMENTS
        MEASUREMENTS:      SPDM 1.2, slot 0, 2 block(s), record 78 B
          [  1] type 8                 digest   48 B  5f91f06163adf14215146e922ce9b1ebc0464e15da4cde9d823452acb62b72e2... (48 B)
          [ 26] type 9                 raw      16 B  "0123456789ab" + 4 B
          nonce:           e0491382faa974fadd3400e0b37bf71ed7b615def4fd853fa9f49df808459833 (32 B)
          opaque:          0 B
          signature:       96 B
    env.smc1:              5743 B
      cert_chain:          4983 B, 6 cert(s)
        [0] CN=DevelopCA             EC secp384r1 2026-09-08..2036-09-05  self-signed
        [1] CN=Caliptra 2.1 Ecc384 IDevID EC secp384r1 2026-09-08..2027-09-08  issued by [0]
        [2] CN=Caliptra 2.1 Ecc384 LDevID EC secp384r1 2023-01-01..9999-12-31  issued by [1]
        [3] CN=Caliptra 2.1 Ecc384 FMC Alias EC secp384r1 2023-01-01..9999-12-31  issued by [2]
        [4] CN=Caliptra 2.1 Ecc384 Rt Alias EC secp384r1 2023-01-01..9999-12-31  issued by [3]
        [5] CN=DPE Leaf              EC secp384r1 2023-01-01..9999-12-31  issued by [4]
      signed_measurements: 722 B
        SPDM transcript:   GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES
                           NEGOTIATE_ALGORITHMS, ALGORITHMS, GET_MEASUREMENTS
                           MEASUREMENTS
        MEASUREMENTS:      SPDM 1.2, slot 0, 2 block(s), record 425 B
          [ 26] type 9                 raw      16 B  "0123456789ab" + 4 B
          [253] type 10                raw     395 B  CBOR Tag(61) CWT / Tag(18) COSE_Sign1
            protected:     1 (alg) = -35 (ES384)
            unprotected:   4 (kid) = 4e1060f07274aeb56409503f163531aa473a7eb1b742eecdacb2721117002a35... (48 B)
            claims
              10 (nonce):  8bed44127666e44b0210622b2f0430b5becb256b53358582197d36f05b5e205b (32 B)
              263 (dbgstat): 1
              265 (profile) > Tag(111): 312e332e362e312e342e312e34323632332e312e33 (21 B) "1.3.6.1.4.1.42623.1.3"
              273 (measurements)
                10571:     a100a1008182a100a300d902304e706c6174666f726d2d737461746501714173... (116 B)
                  0 > 0 > [0]
                    [0] > 0
                      0 > Tag(560): 706c6174666f726d2d7374617465 (14 B) "platform-state"
                      1:       "Aspeed Technology"
                      2:       "AST1040"
                    [1] > [0]
                      0:       0
                      1 > 2 > [0]: [7, 5f91f06163adf14215146e922ce9b1ebc0464e15da4cde9d823452acb62b72e2... (48 B)]
              1 (iss):     "CN=Caliptra EAT DPE Attestation Key"
            signature:     96 B
          nonce:           9a622866cbb35a83f50bdc539e0cfb05f1026fc1ea2dc14b9157185ca55b37d9 (32 B)
          opaque:          0 B
          signature:       96 B

[5] Sleeping 10s before iteration 2
```

With `--format json`, binary values inside the CBOR structure are rendered as
`{"__bytes_hex__": "..."}` (or `{"__bytes_b64__": "..."}` under
`--bytes base64`), CBOR tags as `{"__cbor_tag__": <n>, "value": ...}`
and nested CBOR as `{"__cbor__": ...}`, so the output stays valid JSON. Use
`--save-bundle bundle.cbor` if you need the raw bytes for another tool.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All iterations succeeded |
| `1` | At least one iteration failed |
| `2` | Bad arguments |
| `130` | Interrupted (Ctrl-C) |

## Compatibility notes

Property names vary between OpenBMC builds, so the script accepts more than
one spelling:

* bundle payload: `CompositeEATBundle` (what `ast2700-irot.local` returns),
  `Bundle`, or `EATBundle`
* status: `Status`, `BundleStatus`, or `TaskState`, including the nested
  `{"State": ...}` form; matched case-insensitively, with `InProgress`,
  `In Progress` and `Running` all treated as busy

If a service uses something else, the poller reports
`unexpected status ...` and the Ready path lists the keys it did see.
