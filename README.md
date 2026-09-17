# Composite EAT Bundle Client

A small CLI that walks the OpenBMC Redfish flow for retrieving a **Composite
EAT (Entity Attestation Token) bundle**, then base64- and CBOR-decodes the
result.

## What it does

Each iteration performs:

1. `GET /redfish/v1/ComponentIntegrity/` — show the collection members.
2. `GET` the bundle resource — `/redfish/v1/ComponentIntegrity/CompositeEATBundle`
   — and continue once the status is `Ready` or `Idle` (polls while
   `InProgress`).
3. `POST` the generate action —
   `/redfish/v1/ComponentIntegrity/Actions/Oem/OpenBMCCompositeEATBundle.Generate`
   — with a freshly generated nonce:

   ```json
   { "Nonce": "<base64 of 32 random bytes>" }
   ```

4. `GET` the bundle resource in a loop — sleep 2 s while `InProgress`;
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
chain and detached parts as sizes. It is ~1.3 KB (26 lines) versus ~36 KB
(113 lines) for the JSON form. `--truncate N` sets the preview width here.

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
      33 (x5chain):        7 cert(s), 1465, 772, 907, 674, 811, 536, 531 bytes
        [0] CN=DPE Leaf              EC secp384r1 2023-01-01..9999-12-31  issued by [1]
        [1] CN=Caliptra 1.0 Rt Alias EC secp384r1 2023-01-01..9999-12-31  issued by [2]
        [2] CN=Caliptra 1.0 FMC Alias EC secp384r1 2023-01-01..9999-12-31  issued by [3]
        [3] CN=Caliptra 1.0 LDevID   EC secp384r1 2023-01-01..9999-12-31  issued by [4]
        [4] CN=Caliptra 1.0 IDevID   EC secp384r1 2026-03-21..9999-12-31  issued by [5]
        [5] CN=AST27x0_ECDSA0        EC secp384r1 2026-01-20..9999-12-31  issued by [6]
        [6] CN=ASPEED_CA             EC secp384r1 2025-03-06..9999-12-31  self-signed
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
              10 (nonce):  134cc77bf984305cdb849614bfc4be498fd1071c756f4264560aae9377fdd1c5 (32 B)
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
          nonce:           767c35256868239b6d734f8b394bbc2b8611fa19acc3d02c7d9d3701f9f105c9 (32 B)
          opaque:          0 B
          signature:       96 B
```

Three rules keep even this deep structure short: containers holding a single
child are folded into one `a > b > c` path line instead of a line per level
(CoMID nests heavily); runs of identical array entries are collapsed
(`[4..30]: 27 x 0000...`), which matters for the measurement claim's 32
registers where most are unused; and byte strings that are entirely printable
ASCII get their text shown next to the hex. The full dump with every decoder
enabled is 92 lines (~6.3 KB), 26 lines (~1.3 KB) with none.

Like `--decode-certs`, this is decoding for readability — the SPDM signature
is not verified.

`--format json` gives the full structure instead. There, `--truncate N` cuts
each leaf to the first N bytes (default 128 when passed bare), appends `...`,
and adds a `__bytes_len__` field with the original length — ~36 KB becomes
~6.4 KB at 128.

`--no-cbor` suppresses the decoded dump while still fetching, decoding and
nonce-checking the bundle — useful for long soak runs, where `--save-bundle`
can keep the raw bytes for later inspection. Note that `-q --no-cbor`
together print nothing at all: `-q` silences the step log and `--no-cbor`
removes the only thing it would still print.

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
| `--bundle-path URI` | discovered | Override the bundle resource URI |
| `--action-path URI` | discovered | Override the generate action URI |
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
./composite_eat.py -H ast2700-irot.local -u root -p 0penBmc -n 1000 --truncate 64 --decode-certs --decode-measurements --decode-measurement-cbor
=== Iteration 1/1000 ===
[1] GET /redfish/v1/ComponentIntegrity/
  Name           : Component Integrity Collection
  Members@count  : 2
  Member         : /redfish/v1/ComponentIntegrity/smc0
  Member         : /redfish/v1/ComponentIntegrity/smc1
  Bundle URI     : /redfish/v1/ComponentIntegrity/CompositeEATBundle
  Action URI     : /redfish/v1/ComponentIntegrity/Actions/Oem/OpenBMCCompositeEATBundle.Generate
  ... pausing 5s before step 2
[2] GET /redfish/v1/ComponentIntegrity/CompositeEATBundle
  Status         : ready
  Id             : CompositeEATBundle
  Status         : Ready
  Bundle length  : 25532 (base64 chars)
  ... pausing 5s before step 3
[3] POST /redfish/v1/ComponentIntegrity/Actions/Oem/OpenBMCCompositeEATBundle.Generate
  Nonce          : E0zHe/mEMFzbhJYUv8S+SY/RBxx1b0JkVgquk3f90cU=
  Nonce (hex)    : 134cc77bf984305cdb849614bfc4be498fd1071c756f4264560aae9377fdd1c5
  ... pausing 5s before step 4
[4] GET /redfish/v1/ComponentIntegrity/CompositeEATBundle (poll)
  Status         : ready
  Id             : CompositeEATBundle
  Status         : Ready
  Bundle length  : 25532 (base64 chars)
  Bundle bytes   : 19149 (after base64 decode)
  Profile        : https://github.com/aspeedtech-bmc/profile/composite_eat
  Nonce (token)  : 134cc77bf984305cdb849614bfc4be498fd1071c756f4264560aae9377fdd1c5
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
      34 (x5t):            -43 (SHA-384) 6353d3dea89d10296518d379adc81fa0dd27ad99f250f88506b973f6dd996a73... (48 B)
    unprotected
      33 (x5chain):        7 cert(s), 1465, 772, 907, 674, 811, 536, 531 bytes
        [0] CN=DPE Leaf              EC secp384r1 2023-01-01..9999-12-31  issued by [1]
        [1] CN=Caliptra 1.0 Rt Alias EC secp384r1 2023-01-01..9999-12-31  issued by [2]
        [2] CN=Caliptra 1.0 FMC Alias EC secp384r1 2023-01-01..9999-12-31  issued by [3]
        [3] CN=Caliptra 1.0 LDevID   EC secp384r1 2023-01-01..9999-12-31  issued by [4]
        [4] CN=Caliptra 1.0 IDevID   EC secp384r1 2026-03-21..9999-12-31  issued by [5]
        [5] CN=AST27x0_ECDSA0        EC secp384r1 2026-01-20..9999-12-31  issued by [6]
        [6] CN=ASPEED_CA             EC secp384r1 2025-03-06..9999-12-31  self-signed
    claims
      10 (nonce):          134cc77bf984305cdb849614bfc4be498fd1071c756f4264560aae9377fdd1c5 (32 B)
      256 (ueid):          3512350410323205 (8 B)
      265 (profile):       "https://github.com/aspeedtech-bmc/profile/composite_eat"
      266 (submods)
        env.smc0:          -43 (SHA-384) a06b7c665591c57ad115e943bba977d36712ea81ed699d68a4757870f58ff004... (48 B)
        env.smc1:          -43 (SHA-384) eabc0e4c8101b93a276a585f33794cf3499cd81a6ed0674f3c5161adbb200d37... (48 B)
      273 (measurements)
        application/cbor:  a50198205830adb7976df2fcc3828d282341e43ec49db7e06133de7d4df88260... (1824 B)
          1
            [0]:           adb7976df2fcc3828d282341e43ec49db7e06133de7d4df88260e5c3b7190b29... (48 B)
            [1]:           adb7976df2fcc3828d282341e43ec49db7e06133de7d4df88260e5c3b7190b29... (48 B)
            [2]:           97b1dc9fce4b7b3495abcaa9fc663828fefdf51beddc200192ad434c7b5be3c7... (48 B)
            [3]:           97b1dc9fce4b7b3495abcaa9fc663828fefdf51beddc200192ad434c7b5be3c7... (48 B)
            [4..30]:       27 x 0000000000000000000000000000000000000000000000000000000000000000... (48 B)
            [31]:          93527643023ad308b4c9ffc970106ab50138c23a7ed8b1178359b737954072c8... (48 B)
          2:               32 x 0
          3:               0000000000000000000000000000000000000000000000000000000000000000 (32 B)
          4:               da3774edfde39d8a59d8f1b7fc63831ddbe841c24bf4aa5ad119906b21f81590... (48 B)
          5:               b97144cef01416225bd9293ef71b75161d63e5c5ec4862abf84ff3b315aeeb24... (96 B)
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
          nonce:           ce22c6867e110776a8f58392a2414818d72dd26909993428821c0aa25c8e3f0e (32 B)
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
              10 (nonce):  134cc77bf984305cdb849614bfc4be498fd1071c756f4264560aae9377fdd1c5 (32 B)
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
          nonce:           767c35256868239b6d734f8b394bbc2b8611fa19acc3d02c7d9d3701f9f105c9 (32 B)
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

The bundle and action URIs are **discovered** from the collection's
`Oem.OpenBMC` block on every iteration (`CompositeEATBundle.@odata.id` and the
`Actions` entry whose name contains `CompositeEATBundle`), so a firmware
rename does not need a script change. The discovered URIs are printed under
step 1. If the collection advertises nothing, these defaults are used:

* bundle: `/redfish/v1/ComponentIntegrity/CompositeEATBundle`
* action: `/redfish/v1/ComponentIntegrity/Actions/Oem/OpenBMCCompositeEATBundle.Generate`

Older firmware served `/redfish/v1/ComponentIntegrity/Oem/OpenBMC/CompositeEATBundle/`
and the `OpenBMC.GetCompositeEATBundle` action; `--bundle-path` / `--action-path`
can point at those, or anywhere else, if discovery is not available.

Property names vary between OpenBMC builds, so the script accepts more than
one spelling:

* bundle payload: `CompositeEATBundle` (what `ast2700-irot.local` returns),
  `Bundle`, or `EATBundle`
* status: `Status`, `BundleStatus`, or `TaskState`, including the nested
  `{"State": ...}` form; matched case-insensitively, with `InProgress`,
  `In Progress` and `Running` all treated as busy

If a service uses something else, the poller reports
`unexpected status ...` and the Ready path lists the keys it did see.
