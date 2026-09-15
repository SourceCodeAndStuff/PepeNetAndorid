# PepeNet native core — chain sync + .pepe resolver + DANE TLS proxy.
#
# These are the canonical PepeNet C sources (github.com/PepeNetWeb:
# namespace-indexer + namespace-protocol, pepenet-mesh, pepenet-dns,
# pepenet-tls, and pepenet-desktop's headless engine seams), vendored flat so
# Android Studio can build them with the NDK. Same source set as the Windows
# `pepenet-web` service — nothing re-implemented.
#
# Android: libpepenet_core.so (JNI) · Linux host: pepenet-headless (test harness)
cmake_minimum_required(VERSION 3.22)
project(pepenet_core C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(R ${CMAKE_CURRENT_SOURCE_DIR})
set(PEPENET_VERSION "0.0.1-android")
add_compile_definitions("IDX_DNET_MARK=\"/pepenet-\"" _DEFAULT_SOURCE
                        PEPENET_VERSION="${PEPENET_VERSION}")
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-Wno-unused-parameter -Wno-sign-compare)
endif()

# ── OpenSSL 3 (DANE) + sqlite ────────────────────────────────────────────────
if(ANDROID)
    # OpenSSL 3.5.8 static libs + headers for arm64-v8a / x86_64, shipped as one
    # archive (beeware/cpython-android-source-deps) and unpacked at configure time
    set(OSSL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl)
    if(NOT EXISTS ${OSSL_DIR}/include/openssl/ssl.h)
        file(ARCHIVE_EXTRACT INPUT ${R}/openssl-3.5.8-android.tar.gz DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    endif()
    set(OSSL_LIB ${OSSL_DIR}/${ANDROID_ABI}/lib)
    if(NOT EXISTS ${OSSL_LIB}/libssl.a)
        message(FATAL_ERROR "No prebuilt OpenSSL for ABI ${ANDROID_ABI} (have arm64-v8a, x86_64)")
    endif()
    add_library(ossl_crypto STATIC IMPORTED)
    set_target_properties(ossl_crypto PROPERTIES IMPORTED_LOCATION ${OSSL_LIB}/libcrypto.a
        INTERFACE_INCLUDE_DIRECTORIES ${OSSL_DIR}/include)
    add_library(ossl_ssl STATIC IMPORTED)
    set_target_properties(ossl_ssl PROPERTIES IMPORTED_LOCATION ${OSSL_LIB}/libssl.a
        INTERFACE_INCLUDE_DIRECTORIES ${OSSL_DIR}/include
        INTERFACE_LINK_LIBRARIES ossl_crypto)
    set(SSL_LIBS ossl_ssl ossl_crypto)
    include_directories(BEFORE ${OSSL_DIR}/include)
else()
    find_package(OpenSSL 3 REQUIRED)
    set(SSL_LIBS OpenSSL::SSL OpenSSL::Crypto)
endif()
add_library(pn_sqlite3 STATIC ${R}/sqlite/sqlite3.c)
target_include_directories(pn_sqlite3 PUBLIC ${R}/sqlite)
target_compile_definitions(pn_sqlite3 PRIVATE SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION SQLITE_DQS=0)
find_package(Threads REQUIRED)

# ── libsecp256k1 (single-TU build, ECDH module on) ───────────────────────────
add_library(pn_secp256k1 STATIC
    ${R}/secp256k1/src/secp256k1.c
    ${R}/secp256k1/src/precomputed_ecmult.c
    ${R}/secp256k1/src/precomputed_ecmult_gen.c)
target_include_directories(pn_secp256k1 PUBLIC ${R}/secp256k1/include)
target_include_directories(pn_secp256k1 PRIVATE ${R}/secp256k1/src)
target_compile_definitions(pn_secp256k1 PRIVATE ENABLE_MODULE_ECDH=1
    ECMULT_WINDOW_SIZE=15 COMB_BLOCKS=43 COMB_TEETH=6)

set(SM ${R}/protocol/src)
set(IDX ${R}/indexer)
set(DESK ${R}/desktop)

# ── chain engine: protocol fold + headless indexer + desktop engine seam ─────
add_library(pn_engine STATIC
    ${SM}/fold.c ${SM}/decode.c ${SM}/oracle.c ${SM}/digest.c ${SM}/state.c
    ${SM}/lease.c ${SM}/market.c ${SM}/claim.c ${SM}/trade.c ${SM}/bitmap.c
    ${SM}/preblock.c ${SM}/sha256.c ${SM}/ripemd160.c ${SM}/gen.c
    ${SM}/harness.c ${SM}/ecmh.c
    ${IDX}/attrib.c ${IDX}/adapter.c ${IDX}/oracle_feed.c ${IDX}/db.c
    ${IDX}/chain.c ${IDX}/base58.c ${IDX}/sync.c ${IDX}/pow.c
    ${IDX}/serve_store.c ${IDX}/txcheck.c ${IDX}/mempool.c
    ${R}/protocol/shim/secp_shim.c
    ${DESK}/engine.c ${DESK}/fee.c)
# quoted "secp256k1.h" in indexer sources must hit the vendored libsecp header
# before the protocol dir's same-named one (indexer Makefile: -Isrc -ISECP -ISM)
target_include_directories(pn_engine PUBLIC ${IDX} ${R}/secp256k1/include ${SM} ${DESK})
target_link_libraries(pn_engine PUBLIC pn_secp256k1 pn_sqlite3 Threads::Threads)

# ── pepenet-mesh (sp_*) — protocol headers only, never libsecp's ─────────────
add_library(pn_mesh STATIC
    ${R}/mesh/src/crypto.c ${R}/mesh/src/view.c ${R}/mesh/src/wire.c ${R}/mesh/src/state.c)
target_include_directories(pn_mesh PUBLIC ${R}/mesh/include)
target_include_directories(pn_mesh PRIVATE ${SM})
target_link_libraries(pn_mesh PUBLIC pn_sqlite3)

# ── pepenet-dns + dnsnet seam ────────────────────────────────────────────────
add_library(pn_dns STATIC
    ${R}/dns/dns_state.c ${R}/dns/dns_chain.c ${R}/dns/dns_net.c ${R}/dns/zone.c
    ${R}/dns/dns_wire.c ${R}/dns/dnsd_core.c
    ${DESK}/dnsnet.c ${DESK}/dirscan.c ${DESK}/zonekey.c)
target_include_directories(pn_dns PUBLIC ${R}/dns)
target_include_directories(pn_dns PRIVATE ${SM} ${DESK} ${IDX})
target_link_libraries(pn_dns PUBLIC pn_mesh pn_sqlite3)

# ── pepenet-tls DANE proxy + webproxy seam ───────────────────────────────────
add_library(pn_tls STATIC
    ${R}/tls/ca.c ${R}/tls/proxy.c ${R}/tls/dane.c ${R}/tls/resolve.c
    ${R}/tls/origin.c ${R}/tls/sscert.c ${R}/tls/fetch.c
    ${DESK}/webproxy.c ${R}/core/platform_min.c)
target_include_directories(pn_tls PUBLIC ${R}/tls)
target_include_directories(pn_tls PRIVATE ${DESK})
target_link_libraries(pn_tls PUBLIC pn_dns ${SSL_LIBS})

set(CORE_LIBS pn_tls pn_dns pn_mesh pn_engine pn_secp256k1 ${SSL_LIBS} pn_sqlite3 Threads::Threads)
set(CORE_INC ${DESK} ${IDX} ${R}/secp256k1/include ${SM} ${R}/tls ${R}/dns ${R}/mesh/include)

if(ANDROID)
    add_library(pepenet_core SHARED ${R}/core/pn_core.c ${R}/core/jni_bridge.c)
    target_include_directories(pepenet_core PRIVATE ${CORE_INC})
    target_link_libraries(pepenet_core PRIVATE -Wl,--start-group ${CORE_LIBS} -Wl,--end-group log)
    # 16 KB pages (Android 15+ devices)
    target_link_options(pepenet_core PRIVATE -Wl,-z,max-page-size=16384)
else()
    add_executable(pepenet-headless ${R}/core/pn_core.c ${R}/core/headless_main.c)
    target_include_directories(pepenet-headless PRIVATE ${CORE_INC})
    target_link_libraries(pepenet-headless PRIVATE -Wl,--start-group ${CORE_LIBS} -Wl,--end-group)
endif()
