# native/ — the PepeNet node, built into the app with the NDK

Vendored, unmodified sources from github.com/PepeNetWeb (pinned by pepenet-desktop 0.2.3):

| dir         | from                                                     |
|-------------|----------------------------------------------------------|
| protocol/   | namespace-protocol `impls/c/src` + `shim/secp_shim.c`     |
| indexer/    | namespace-indexer `src` (chain sync over Pepecoin P2P)   |
| secp256k1/  | libsecp256k1 (indexer's pin; `src`, `include`, ECDH)     |
| mesh/       | pepenet-mesh                                              |
| dns/        | pepenet-dns (zone store + resolver core)                 |
| tls/        | pepenet-tls (name-constrained CA + DANE proxy)           |
| desktop/    | pepenet-desktop headless engine seams (engine/dnsnet/webproxy) |

Added for Android: `core/` (pn_core.c boot/stop/status, jni_bridge.c, platform_min.c;
headless_main.c is a Linux test harness), `sqlite/` (amalgamation 3.53.4),
`openssl-3.5.8-android.tar.gz` (OpenSSL 3.5.8 headers + static libs, unpacked by CMake at configure time, for arm64-v8a + x86_64, from
beeware/cpython-android-source-deps).

Desktop test: `cmake -S native -B build && cmake --build build && ./build/pepenet-headless /tmp/pn`
