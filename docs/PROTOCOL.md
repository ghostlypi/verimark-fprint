# VeriMark Desktop 2.0 protocol

Reverse engineered from a USBPcap capture of one complete Windows Hello
enrollment, then verified command-by-command against the hardware. Device is
`047d:8228`, Realtek RTS5816-class match-on-chip silicon under Kensington's
vendor ID. Windows INF is `KensingtonMocWbdi.inf`; the vendor user-mode
drivers are `AtansMoc*.dll`.

## Transport

Bulk only. `EP OUT 0x01`, `EP IN 0x82`. The interrupt endpoint `0x83` exists
but is never used.

Every command is a 12-byte packet on `EP OUT`:

```
[cmd0][cmd1][param 4][addr 4][data_len u16le]
```

`cmd0 >> 6` selects the shape: `0` = status only, `1` = device→host payload,
`2` = host→device payload. `addr` is always zero on this device.

A read command is followed by `data_len` bytes on `EP IN`, then a 5-byte
status. A write command is followed by the payload on `EP OUT`, then the
status. Status is `[status u8][err i32le]`.

**A non-zero status is not always an error.** Several perfectly normal
outcomes — "no duplicate found", "no match" — come back as `status=1,
err=-9` alongside a meaningful payload. Upstream libfprint already models this
with `FP_RTK_MSG_NO_STATUS` for exactly these commands.

## Opcodes

| cmd | type | data | meaning |
|---|---|---|---|
| `40 06` | read | 8 | read device property, index in `param` |
| `05 13` | none | – | select OS; accepts 0–7 and changes nothing observable |
| `45 0d` | read | 2 | `[?][slot capacity]` |
| `45 0e` | read | 520 | template table |
| `05 05` | none | – | start capture, `param = [purpose, 0x02]` |
| `45 06` | read | 5 | poll, `param = [purpose, 0x02]`; `[state][u32]` |
| `45 08` | read | 9 | accept sample, `param = [purpose]` |
| `05 07` | none | – | cancel capture, `param = [purpose]` |
| `45 10` | read | 34 | check duplicate |
| `05 0f` | none | – | delete slot, `param = [slot]` |
| `85 01` | write | 101 | SDCP connect |
| `45 02` | read | 1206 | SDCP connect response |
| `85 03` | write | 34 | SDCP reconnect |
| `45 04` | read | 34 | SDCP reconnect response |
| `45 09` | read | 32 | enrollment nonce, `param = 0` |
| `85 0a` | write | 49 | enrollment commit, `param = [subfactor]` |
| `85 0b` | write | 32 | identify nonce |
| `45 0c` | read | 74 | identify |

Purposes: `1` verify, `2` identify, `4` enroll.

`45 09` is the exception: it takes no purpose. Passing `4` — the obvious guess,
and what every neighbouring command wants — is rejected with `status 1,
error -9` and a zero nonce, which reads exactly like "enrollment is refused"
rather than "wrong parameter".

Poll states: `3` no finger, `1` finger present, `0` captured.

Sample verdicts are libfprint's `FpRtkInStatus`: `0` success, `1..10` quality
complaints, `11` no match, `12` command error.

### Two commands to avoid

- **`85 21`** is upstream libfprint's commit opcode. This firmware does not
  implement it and does not drain the data phase; probing it leaves the chip
  wedged until it is physically unplugged. A USB reset and a sysfs
  de-authorize both fail to clear it.
- **`05 0f` with `param = 0xff`** erases every template on the device, across
  all operating systems and users. Only ever pass a slot index you located.

## Differences from libfprint's `realtek` driver

Four, and only one of them is SDCP:

1. **Template stride is 52 bytes, not 35.** The table is `10 × 52 = 520`.
   Upstream computes `TEMPLATE_LEN_COMMON (35) × slots`, which misaligns every
   slot after the first — free-slot scanning and identifier extraction both
   read garbage.
2. **`05 05` and `45 06` need the purpose in `param`.** Upstream leaves it
   zero.
3. **Commit is `85 0a` / `param 0xf5` / 49 bytes**, not `85 21` / `0xff` / 32.
4. **Enrollment requires an SDCP session.**

Record layout:

```
[0]      valid flag
[1]      sub-template count
[2]      subfactor (echoes the commit's param[0], 0xf5)
[3..34]  SHA-256 of the enrollment_id
[35..41] 7 bytes of opaque host metadata, stored verbatim
[42..51] padding
```

The chip stores the *hash* of the enrollment identifier. The raw identifier is
returned on a match, never read back from storage.

## SDCP

[Microsoft's Secure Device Connection Protocol](https://github.com/microsoft/SecureDeviceConnectionProtocol).
`AtansMocWbdi.dll` contains `sdcpcli_keygen`, `sdcpcli_secret_agreement`,
`master secret`, `application keys` and the `connect`/`reconnect`/`identify`/
`enroll` labels, which is what identified it.

### Handshake

```
85 01  ->  [u16 32][HostRandom 32][u16 65][0x04 || X || Y]        101 bytes
45 02  <-  [u16 32][DeviceRandom][u16 1098][claim][u16 32][ClaimMAC][38 pad]
85 03  ->  [u16 32][HostRandom2]                                   34 bytes
45 04  <-  [u16 32][ReconnectionMAC]                               34 bytes
```

```
claim = certificate(808) || DevicePublicKey(65) || FirmwarePublicKey(65)
        || FirmwareHash(32) || ModelSignature(64) || DeviceSignature(64)
```

**Both exchanges are required.** `45 09` returns `-9` until the reconnect
response has been consumed — this is the single thing that makes enrollment
appear impossible if you only implement `85 01`/`45 02`.

### Key schedule

```
shared        = ECDH(host_ephemeral_private, FirmwarePublicKey)
master_secret = KDF(shared,        "master secret\0",    HostRandom||DeviceRandom, 256)
MAC_secret    = KDF(master_secret, "application keys\0", "",                       512)[0:32]
```

`KDF` is NIST SP 800-108 counter mode with HMAC-SHA256:

```
K(i) = HMAC(key, be32(i) || Label || 0x00 || Context || be32(L))
```

The label's NUL terminator is part of the input. `L` is the output length in
*bits*, big-endian.

Key agreement is against the **firmware** public key, not the device public
key. The device key signs the firmware key; the firmware key is the
key-agreement key. Using the wrong one is silent — you get a plausible key that
fails only at the first MAC check.

### Derived values

```
ClaimMAC          = HMAC(MAC_secret, "connect\0"   || SHA256(claim))
ReconnectionMAC   = HMAC(MAC_secret, "reconnect\0" || HostRandom2)
enrollment_id     = HMAC(MAC_secret, "enroll\0"    || nonce_from_45_09)
AuthenticationMAC = HMAC(MAC_secret, "identify\0"  || nonce || enrollment_id)
```

`ClaimMAC` is the useful one when bringing this up: it arrives in the connect
response, so a client can validate its entire key derivation offline after a
single exchange, before attempting anything else.

## Flows

**Enroll** — connect, reconnect, `45 09` for the nonce, then N× of
(`05 05 param=[4,2]`, poll `45 06`, `45 08 param=[4]`), then `45 10` expecting
`0x0b`, then `85 0a param=[0xf5]` with `enrollment_id || 17 zero bytes`.

The 17-byte tail is opaque host metadata. Windows puts its own there; the
device stores whatever you send verbatim and zeros work fine.

There is no "enrollment complete" signal — the host decides how many samples to
take. Windows Hello takes 12.

**Identify** — `05 05 param=[2,2]`, poll, `45 08 param=[2]`, then `85 0b` with
a 32-byte nonce, then `45 0c param=[0,2]`:

```
[status][subfactor][enrollment_id 32][AuthenticationMAC 32][8 bytes]
```

Verify the MAC over your own nonce before believing the match. That check is
the entire point of SDCP.
