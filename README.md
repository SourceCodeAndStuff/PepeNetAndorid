# PepeNet for Android

Browse `.pepe` websites on Android with a real padlock. The app runs a full
PepeNet node on the phone — Pepecoin chain sync, the `.pepe` zone mesh and
resolver, and the DANE-enforcing TLS proxy — built from the canonical
[PepeNetWeb](https://github.com/PepeNetWeb) C sources.

**Version 0.0.1** · Android 10+ · arm64 phones and x86_64 emulators

## Download

[**PepeNet-0.0.1.apk**](releases/PepeNet-0.0.1.apk?raw=1) — enable "Install unknown apps" for your
browser or file manager, then open the file.

## Using it

1. Tap **Connect** and allow the VPN request. The first connect syncs name data
   from Pepecoin peers; the status line shows progress.
2. Install the `.pepe` certificate when prompted (one-time). Android does not let
   apps do this silently, so the app saves `PepeNet-pepe-root.crt` to Downloads
   and opens Settings:
   - Samsung: Security and privacy › More security settings › Install from device storage › CA certificate
   - Pixel/others: Security › Encryption & credentials › Install a certificate › CA certificate
3. Restart Chrome. The directory of `.pepe` domains unlocks in the app: favicon,
   online status, the owner's `_site` TXT description and search. Tap a domain to open it.

The certificate carries a critical X.509 Name Constraint — it can only vouch for
`*.pepe` names, never for any other website.

## How it works

| Piece | Where |
|---|---|
| Chain sync, `.pepe` resolver (127.0.0.1:15353), DANE proxy (127.0.0.1:8443, CONNECT door :8444) | `native/` (C, NDK) |
| JNI bridge + directory export | `native/core/` |
| VPN: hands Android an HTTP proxy (127.0.0.1:8480) so browsers send `.pepe` to the DANE proxy; answers DNS | `app/.../vpn/` |
| Certificate export + guided install | `app/.../vpn/CertificateManager.kt` |
| Directory, favicon/online probes (trusting only the PepeNet root) | `app/.../directory/` |

## Build

Android Studio (AGP 9.4) with the NDK and CMake installed from SDK Manager.

```
./gradlew :app:publishApk      # → releases/PepeNet-<version>.apk
```

Headless node on Linux for testing: `cmake -S native -B build && cmake --build build && ./build/pepenet-headless /tmp/pn`

## Third-party code

`native/` vendors PepeNetWeb's namespace-protocol, namespace-indexer, pepenet-mesh,
pepenet-dns, pepenet-tls and pepenet-desktop sources, libsecp256k1 (MIT, see
`native/secp256k1/COPYING`), SQLite (public domain) and OpenSSL 3.5.8 static
libraries (Apache-2.0) from beeware/cpython-android-source-deps. See `native/README.md`.
