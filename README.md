# MenuAuth

A native macOS 26 (Tahoe) menu bar authenticator. It imports your accounts from
Google Authenticator's **Transfer accounts → Export** QR code and shows the same
TOTP codes on your Mac, so you stop reaching for your phone.

It is built to sit in the menu bar all day: **no Dock icon, no window, and no
timer running while the panel is closed.**

- **Zero third-party dependencies.** CryptoKit, Vision, AVFoundation,
  LocalAuthentication, Security and SwiftUI only.
- **Scans the real export format**, including multi-QR exports, and also accepts
  a plain `otpauth://totp/...` QR from any site.
- **Secrets live in the Keychain**, never in the metadata file, and are
  overwritten in memory when the app re-locks.

---

## Build and install

Requires macOS 26 and Xcode 26.

```bash
# Run the tests
xcodebuild -project MenuAuth.xcodeproj -scheme MenuAuth \
  -destination 'platform=macOS' test

# Build a Release app and install it
xcodebuild -project MenuAuth.xcodeproj -scheme MenuAuth \
  -configuration Release -destination 'platform=macOS' build

cp -R ~/Library/Developer/Xcode/DerivedData/MenuAuth-*/Build/Products/Release/MenuAuth.app \
  /Applications/
open /Applications/MenuAuth.app
```

Then turn on **Launch at login** in MenuAuth's Settings. That toggle only works
from `/Applications` — `SMAppService` refuses to register an app running out of
DerivedData.

No Apple Developer account is needed; the project signs ad-hoc ("Sign to Run
Locally"). See **Security** below for what that costs you.

## Importing your accounts

On your phone: **Google Authenticator → ⋯ → Transfer accounts → Export
accounts**, pick the accounts, and continue to the QR code.

Then in MenuAuth, click the menu bar icon → **Add**, and pick a source:

| Source | Use it when | Permission |
|---|---|---|
| **Camera** | The QR is on a phone in your hand. | Camera |
| **Screen** | The QR is visible on the Mac — see iPhone Mirroring below. | Screen Recording |
| **Image** | You have a screenshot or photo, or a QR on the clipboard. | None |

The camera only runs while its own tab is selected, so choosing Screen or Image
never turns it on.

### Importing without a camera, via iPhone Mirroring

macOS 26 can mirror your iPhone on the Mac, which means Google Authenticator can
show its export QR *on your screen*. Open iPhone Mirroring, get to the export QR,
then in MenuAuth choose **Screen → Capture Screen**. It grabs every display,
finds the QR wherever it is, and excludes its own panel from the shot so it can't
cover the code.

> Android blanks its screen under capture (`FLAG_SECURE`), so this route is for
> iPhone. Use the Camera or Image tabs on Android.

There is no "sign in with Google" import, because Google exposes no API for it —
the export QR is the only way out of Google Authenticator. See **Why there's no
Google login** below.

**If you have more than a few accounts, Google splits the export across several
QR codes.** MenuAuth tracks this and tells you *"Scanned 1 of 3 — swipe to QR
code 2 on your phone, then capture again"*. Your progress is held at app scope,
not in the panel, so clicking away to swipe to the next QR — which dismisses the
menu bar panel — does not lose the fragments you already scanned. Reopening the
panel drops you straight back into the import.

Rescanning an export you already imported updates those accounts in place rather
than creating duplicates.

## Why there's no Google login

Signing in with Google cannot import your codes, and this is not a gap in
MenuAuth — Google exposes no way to do it.

- No OAuth scope or API returns Authenticator secrets. Every tool that moves
  codes out of Google Authenticator, including the reference decoders this
  project was checked against, goes through the export QR.
- Google Authenticator's cloud sync *does* store your seeds in your Google
  account, but only Authenticator app instances can read them, over an
  unpublished internal protocol. Reaching it would mean impersonating the app.
- It is deliberate. A Google sign-in is a *first* factor. If it could hand back
  every TOTP seed, every other site's second factor would reduce to "whoever has
  the Google password".

The screen-capture path above exists because it removes the real friction —
juggling a phone in front of a camera — without needing an API that does not and
should not exist.

## Security

Secrets live in `secrets.dat`, encrypted with AES-GCM. The Keychain holds
exactly **one** item: the key to that file, `ThisDeviceOnly` and non-syncable.
Account names, issuers and digit counts live separately in `accounts.json` (mode
`0600`), which is what lets the panel draw your account list and countdown rings
without ever prompting you. Both files sit in
`~/Library/Application Support/com.anhtd.MenuAuth/`.

Codes are hidden behind Touch ID, and copying one marks the clipboard entry
`org.nspasteboard.ConcealedType` so clipboard managers skip it.

### Why one Keychain item and not one per account

macOS asks for your login password once per Keychain item *access control list*.
The first version stored one item per account, so twenty-four accounts meant
twenty-four password prompts — and **"Always Allow" only authorises the one item
it was shown for**, so clicking it never fixed the next twenty-three.

Now there is a single item, so there is a single prompt. `secrets.dat` is
useless without it. `"Many accounts still occupy exactly one Keychain item"`
asserts this with twenty-five accounts, because item count *is* prompt count.

Installs from before this change are migrated automatically on first unlock:
the old per-account items are read, folded into the encrypted file, and deleted.

### If the prompt keeps coming back

An ad-hoc signed build has no stable code identity — every rebuild changes its
`cdhash`, so macOS treats it as a different app and every previously granted
"Always Allow" stops matching. One rebuild, one fresh prompt.

Setting a **Team** in Xcode (Signing & Capabilities; a free Apple ID works) gives
the app a stable identity, so "Always Allow" survives rebuilds — and, as above,
also unlocks the stronger Keychain-enforced Touch ID gate.

### How strong the Touch ID gate is depends on how you sign the app

This is worth understanding, because MenuAuth reports it in Settings rather than
overstating it.

| Signing | Gate | What it resists |
|---|---|---|
| Ad-hoc (default, no Apple account) | **App-enforced.** MenuAuth asks for Touch ID before revealing codes. | Someone at your unlocked Mac. |
| Signed with an Apple Developer team | **Keychain-enforced.** The Keychain itself refuses to release a secret without Touch ID. | The above, plus code running as you. |

The stronger mode needs the *data-protection* Keychain, which requires an
`application-identifier` or `keychain-access-groups` entitlement. An ad-hoc build
has neither, and `SecItemAdd` returns `errSecMissingEntitlement` (-34018) — this
is verified by a test, not assumed.

**To upgrade:** open the project in Xcode, select the MenuAuth target →
Signing & Capabilities → set **Team** to your Apple ID (a free account is
enough), and rebuild. `KeychainAvailability` probes at launch, detects the
entitlement, and switches to the enforced path automatically. No code change.

The app never silently pretends: asking the legacy Keychain for a gate it cannot
enforce throws rather than storing an ignored access-control attribute.

### Verifying the biometric gate by hand

The automated tests deliberately use unprotected items so they never block on a
Touch ID prompt. To check the gate itself:

1. Open the panel — codes read `••• •••`.
2. Click **Unlock to show codes** and authenticate. Codes appear.
3. Lock the screen, or click the padlock in the footer, or wait out the idle
   timeout in Settings.
4. Reopen the panel — codes are hidden again and a new prompt is required.

## How it stays cheap

The footprint work is structural, not micro-optimisation:

- **`LSUIElement`, no window.** AppKit skips the Dock tile, main menu and window
  restoration entirely.
- **One timer, only while visible.** `CodeClock` is started in the panel's
  `onAppear` and cancelled in `onDisappear`. A closed panel schedules nothing.
- **One HMAC per account per 30 s.** The 1 Hz tick only drives the countdown
  ring. A code is recomputed only when its RFC 6238 time step changes — asserted
  by `"A code is computed once per period, not once per tick"`.
- **The countdown ring does not animate.** Tweening it would re-render every
  visible row every frame; stepping once a second is free and just as readable.
- **The camera is built and destroyed with the import view.** An idle
  `AVCaptureSession` is the most expensive thing this app could leave running.
- **Camera frames are analysed four times a second, not sixty.** A QR held up to
  a camera does not change per frame, so `QRFrameAnalyzer` throttles Vision to
  ~4 Hz and the capture runs at 720p rather than full resolution.

### A note on the camera path

QR scanning on iOS is normally done with `AVCaptureMetadataOutput`, and that is
what this app used first. On macOS it reported no support for the QR type at all,
so the scanner dead-ended with *"This Mac's camera can't detect QR codes."*

The camera now uses `AVCaptureVideoDataOutput` and decodes frames with Vision —
the same decoder the Screen and Image tabs already used, so all three paths share
one implementation. `QRFrameAnalyzerTests` renders a QR into a `CVPixelBuffer`
and pushes it through that decoder, so the live-camera path is covered by tests
without needing a camera.

### Measured, not assumed

Sampling cumulative CPU time every 2 s across an open/close cycle:

```
  2s … 30s   0:03.32   ← panel closed: 15 identical samples
 32s … 74s   0:03.43 → 0:06.59   ← panel open: steady ramp, ~4%
 76s … 166s  0:06.59   ← panel closed again: 45 identical samples over 90s
```

With the panel closed the counter does not move at all — one distinct value
across 45 consecutive samples. A 15-second `sample` of the process in that state
shows the main thread parked in the run loop for all 13,048 samples, with no
timer, no `CodeClock`, and no SwiftUI body evaluation. The ~4 % while open is 1 Hz
rendering, which only happens in the seconds you are actually looking at it.

Reproduce it with:

```bash
PID=$(pgrep -x MenuAuth)
for i in $(seq 1 45); do ps -o time= -p $PID; sleep 2; done
sample $PID 15            # main thread should be parked in runApp throughout
vmmap --summary $PID | grep "Physical footprint"
```

**On the memory numbers:** physical footprint — what Activity Monitor calls
Memory — sits around 15 MB. `ps` RSS reads ~114 MB, but that is mapped framework
text: linking ScreenCaptureKit pulls in ReplayKit, and Vision pulls in Espresso,
libfaceCore and VisionCore. Those pages are clean, shared with every other app
using them, and evictable, so they are not a real cost. Only the ~15 MB is.

Open the import view, close it again, and re-check the footprint: it should
return to baseline, which is what proves the capture session was torn down
rather than merely stopped.

## Testing

```bash
xcodebuild -project MenuAuth.xcodeproj -scheme MenuAuth \
  -destination 'platform=macOS' test
```

The suite covers the parts where being subtly wrong is invisible:

- **All 18 RFC 6238 vectors** across SHA-1/256/512, plus leading-zero
  preservation and exact time-step arithmetic at large timestamps.
- **RFC 4648 base32**, including the lowercase/spaced/unpadded forms sites
  actually present.
- **Two real published export payloads**, decoded field by field. One of them
  omits the `type` field entirely — which is why the decoder treats "unspecified"
  as TOTP instead of rejecting it.
- **The two classic importer bugs**: `digits` is an *enum* (1 = six, 2 = eight),
  and the `data=` parameter must not be form-decoded, or `+` becomes a space and
  silently corrupts every secret.
- **Multi-QR assembly**: out-of-order fragments, repeated scans from a live
  camera, and fragments from a different export.
- **Import session persistence**: a half-scanned batch survives the panel being
  dismissed, a repeated capture is silent, and a stray QR mid-batch does not
  clobber the "swipe to QR 2" prompt.
- **The clock's start/stop contract**, including that a stopped clock is
  genuinely inert and that resigning active stops it.
- **Round trip**: an export QR string all the way through to the six digits the
  panel displays.

## Layout

```
MenuAuth/
├── Core/          TOTP, base32, protobuf reader, migration + otpauth decoders
├── Storage/       Keychain, availability probe, secret vault, metadata, store
├── Security/      Touch ID gate, idle and screen-lock re-locking
├── Scan/          camera, screen capture, image decoding, multi-QR assembly,
│                  and the import session that outlives the panel
└── UI/            menu bar panel, rows, countdown ring, import, settings
```

## Limits

- TOTP only. Counter-based (HOTP) accounts are counted and reported at import,
  not stored.
- No iCloud sync, by design — secrets are marked `ThisDeviceOnly`.
- No manual secret entry; import is by QR (camera, image, or clipboard).
