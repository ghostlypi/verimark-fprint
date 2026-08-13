# verimark-fprint

A Linux fingerprint driver for the **Kensington VeriMark Desktop 2.0**
(USB `047d:8228`), with working **enrollment and matching** — no vendor blob,
no Windows required.

It ships as a [libfprint-tod](https://gitlab.freedesktop.org/3v1n0/libfprint/tree/tod)
plugin, so it drops in alongside your distribution's libfprint and survives
updates to it. Once installed, the reader shows up in GNOME Settings and works
for login, `sudo` and polkit like any supported sensor.

## Why this exists

The VeriMark Desktop 2.0 is Realtek RTS5816-class match-on-chip silicon sold
under Kensington's USB vendor ID. libfprint already has a `realtek` driver that
speaks most of its transport, but it does not recognise this device, and three
of its assumptions are wrong for this firmware. More importantly, the firmware
refuses to store a template unless the host has completed Microsoft's **Secure
Device Connection Protocol** handshake.

That last part is the reason this device has been unusable on Linux. libfprint
has no SDCP support — it was [proposed in 2020](https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/257)
and never implemented. This driver implements the client side.

Matching is *not* gated by SDCP; only enrollment is. That is a deliberate
design: an attacker with the device should not be able to silently add their own
finger. This driver nevertheless verifies the sensor's authentication MAC on
every match, which is the property SDCP exists to provide.

## Install

```
sudo dnf install ./verimark-fprint-0.1.0-1.fc44.x86_64.rpm
```

Installing only puts the driver in place. To turn on fingerprint
authentication for login, sudo and polkit:

```
sudo verimark-setup enable     # and "disable" to turn it back off
```

**Your password keeps working either way** — fingerprint auth is additive, so a
sensor that stops responding can never lock you out.

> **Run `verimark-setup enable` from a TTY, or right after a fresh boot.**
> It calls `authselect`, which regenerates the system dconf databases; on
> GNOME 50.4 that reliably segfaults `gnome-shell` in `update_clock()` and ends
> the session, losing unsaved work. It is a gnome-shell bug — the fingerprint
> stack is not involved — but this is the command that triggers it, so the tool
> asks before proceeding. The package deliberately does *not* run it for you.

Then enroll a finger in **GNOME Settings → Users → Fingerprint Login**, or:

```
fprintd-enroll -f right-index-finger
```

## Checking it works

```
sudo verimark-diag info      # device details + templates stored on the sensor
sudo verimark-diag verify    # touch the sensor, see what it matches
verimark-setup status        # PAM state, driver presence, enrolled fingers
```

## Build from source

```
meson setup build
ninja -C build
sudo ninja -C build install
sudo systemctl try-restart fprintd
```

Requires `libfprint-tod-devel`, `openssl-devel` (3.0+), `glib2-devel`.
On Fedora, `libfprint-tod-devel` comes from the
`copr.fedorainfracloud.org/grahamwhiteuk/libfprint-tod` repository.

To test a build without installing it:

```
sudo FP_TOD_DRIVERS_DIR=$PWD/build/src verimark-diag info
```

## Templates enrolled elsewhere

The sensor stores templates on-chip, and this driver reads the same table the
Windows driver writes. A finger enrolled under Windows Hello is therefore
already usable — it just isn't *claimed* by anyone, because fprintd separately
keeps a host-side note of which template belongs to which user and finger.

`verimark-diag adopt` writes that note, so an existing template can be used for
login without re-enrolling it:

```
sudo systemctl stop fprintd
sudo verimark-diag adopt --finger right-index-finger
sudo systemctl start fprintd
```

It asks for a touch and adopts whichever template you actually match, so the
finger you name is the finger you get. With a single template on the sensor,
`--no-touch` skips that. New fingers still enroll normally — adoption and
enrollment are independent.

Nothing is copied off the sensor by this: the host record holds the same
`SHA-256(enrollment_id)` the chip already returns from a plain template
listing, which is what matching compares anyway.

## What a template on the sensor can and cannot do

A template sitting on the sensor authenticates nobody. The sensor is shared —
across operating systems, across user accounts, and across anyone who has
physical possession of it — so a template alone is treated as a claim, not a
credential.

What makes one usable is a *host record*: a file under
`/var/lib/fprint/<user>/verimark/<device>/<finger>`, in a directory that is
`0700 root:root`. fprintd hands pam_fprintd only the records belonging to the
user being authenticated, and this driver requires the sensor's answer to equal
one of them. `verimark-diag info` shows which templates are claimed:

```
templates stored on the sensor: 4
  [0] claimed by pi as right-index
  [1] claimed by pi as left-index
  [2] UNCLAIMED — on the sensor, but no host record.
  [3] UNCLAIMED — on the sensor, but no host record.
```

So a finger enrolled under Windows, or by another user, or by someone who
walked up with the reader, cannot log you in. Claiming one takes root — which
is to say, it takes an administrator deciding to.

Forging a claim is not practical either. The host record stores
`SHA-256(enrollment_id)`, and `enrollment_id` is
`HMAC(MAC_secret, "enroll\0" || nonce)` where `MAC_secret` comes from an
ephemeral ECDH exchange. Anyone can enroll their own finger into a free slot,
but they cannot produce one whose hash matches an existing record, and the raw
identifier is never stored on the chip.

What an attacker with the device *can* do is fill the ten slots, or delete
templates. Both are denial of service, not impersonation.

### Fingerprint at the login screen

On a Fedora system with `with-fingerprint` enabled, GDM will accept a
fingerprint at the *initial* login, not just to unlock a running session —
`/etc/pam.d/gdm-fingerprint` runs `pam_fprintd` on its own. From a cold boot,
your finger alone gets in; no password is required first.

That is the distribution default, and it is a deliberate trade. Note that GNOME
uses the same `gdm-fingerprint` stack for unlocking a running session as it does
for logging in, so simply disabling it removes fingerprint unlock too — leaving
the reader useful only for `sudo` and polkit. Getting "password once per boot,
fingerprint thereafter" requires distinguishing the two by whether the user
already has a session, which this package does not currently do.

## Storage limits

The sensor holds **10 templates**, shared across every OS and user. `verimark-diag
info` shows how many are in use. Deleting a print in GNOME Settings frees its
slot on the chip.

## Protocol

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the wire format, the SDCP key
schedule, and the specific ways this firmware differs from what upstream
libfprint's `realtek` driver expects.

## Status and caveats

- Enrollment, matching, listing and deletion all work.
- Enrollment takes 12 touches. The firmware gives no "enrollment complete"
  signal, so the count is chosen by the host; 12 is what Windows Hello uses.
- Only `047d:8228` is claimed. Genuine Realtek-branded sensors are left to
  libfprint's own `realtek` driver, which is correct for them.
- Not submitted upstream. The right long-term home for the SDCP client is
  libfprint itself, where every match-on-chip driver could use it.

## License

BSD-3-Clause.

The driver is written against libfprint's public device API and loaded by it as
a plugin; libfprint itself is LGPL-2.1-or-later, which permits exactly that. The
layout of a match-on-chip driver here follows how libfprint's own `realtek`
driver is organised, since this device speaks the same transport. The SDCP
client is written from Microsoft's public specification.
