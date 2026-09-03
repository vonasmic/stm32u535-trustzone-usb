cmake_minimum_required(VERSION 3.21.0)
if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.24")
    cmake_policy(SET CMP0135 NEW)
endif()

project(se_tropic_model_tests
        DESCRIPTION "SE_firmware Tropic runtime tests against TROPIC01 model"
        LANGUAGES C)

if(NOT UNIX)
    message(FATAL_ERROR "TROPIC01 model tests require Linux (WSL2).")
endif()

file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../libtropic" PATH_LIBTROPIC)
file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../Secure/Core" PATH_SECURE_CORE)
file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/_deps" PATH_DEPS)

if(NOT EXISTS "${PATH_DEPS}/wolfssl")
    message(FATAL_ERROR "Dependencies missing. Run: bash host/tropic_model/download_deps.sh")
endif()

set(MODEL_CFG_PATH "${PATH_LIBTROPIC}/scripts/tropic01_model/model_cfg.yml" CACHE STRING "")
set(RUN_LOGS_DIR "${CMAKE_CURRENT_BINARY_DIR}/run_logs/" CACHE STRING "")
set(MODEL_VENV "${PATH_LIBTROPIC}/scripts/tropic01_model/.venv" CACHE PATH "")

###########################################################################
# libtropic + wolfcrypt CAL + POSIX TCP HAL
###########################################################################
add_subdirectory(${PATH_LIBTROPIC} "libtropic")
target_compile_options(tropic PRIVATE -ffunction-sections -fdata-sections)

# Model SH0 is prod0 (see model_cfg.yml)
target_compile_definitions(tropic PUBLIC
    LT_USE_SH0_PROD0=1
    LT_USE_SH0_ENG_SAMPLE=0
)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(WOLFSSL_EXAMPLES OFF CACHE BOOL "" FORCE)
set(WOLFSSL_CRYPT_TESTS OFF CACHE BOOL "" FORCE)
set(WOLFSSL_AESGCM ON CACHE BOOL "" FORCE)
set(WOLFSSL_SHA256 ON CACHE BOOL "" FORCE)
set(WOLFSSL_SHA384 ON CACHE BOOL "" FORCE)
set(WOLFSSL_HKDF ON CACHE BOOL "" FORCE)
set(WOLFSSL_CURVE25519 ON CACHE BOOL "" FORCE)
set(WOLFSSL_ECC ON CACHE BOOL "" FORCE)
set(WOLFSSL_EXPERIMENTAL ON CACHE BOOL "" FORCE)
set(WOLFSSL_MLKEM ON CACHE BOOL "" FORCE)
set(WOLFSSL_SHA3 ON CACHE BOOL "" FORCE)
set(WOLFSSL_SHAKE128 ON CACHE BOOL "" FORCE)
set(WOLFSSL_SHAKE256 ON CACHE BOOL "" FORCE)
set(WOLFSSL_TLS13 ON CACHE BOOL "" FORCE)
set(WOLFSSL_KEYING_MATERIAL ON CACHE BOOL "" FORCE)
add_subdirectory("${PATH_DEPS}/wolfssl" "wolfssl")
# Native ML-DSA-44 (cmake only pulls dilithium.c when WOLFSSL_OQS is on).
# WOLFSSL_WC_DILITHIUM is required so dilithium.h defines LEVEL5 max sizes.
target_sources(wolfssl PRIVATE "${PATH_DEPS}/wolfssl/wolfcrypt/src/dilithium.c")
target_compile_definitions(wolfssl PUBLIC
    HAVE_DILITHIUM
    WOLFSSL_WC_DILITHIUM
    WOLFSSL_HAVE_MLDSA
    WOLFSSL_NO_ML_DSA_65
    WOLFSSL_NO_ML_DSA_87
    HAVE_KEYING_MATERIAL
)

add_subdirectory("${PATH_LIBTROPIC}/cal/wolfcrypt" "wolfcrypt_cal")
target_sources(tropic PRIVATE ${LT_CAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_CAL_INC_DIRS})
target_link_libraries(tropic PUBLIC wolfssl)
target_compile_definitions(tropic PUBLIC WOLFSSL_NO_OPTIONS_H LT_USE_WOLFCRYPT=1)

add_subdirectory("${PATH_LIBTROPIC}/hal/posix/tcp" "posix_tcp_hal")
target_sources(tropic PRIVATE ${LT_HAL_SRCS})
target_include_directories(tropic PUBLIC ${LT_HAL_INC_DIRS})

###########################################################################
# Shared SE Tropic runtime (same sources as firmware, host port)
###########################################################################
set(SE_TROPIC_RUNTIME
    ${PATH_SECURE_CORE}/Src/se_tropic.c
    ${PATH_SECURE_CORE}/Src/se_tropic_pin.c
    ${PATH_SECURE_CORE}/Src/se_tropic_rmem.c
    ${PATH_SECURE_CORE}/Src/se_tropic_mlkem.c
    ${PATH_SECURE_CORE}/Src/se_tropic_session.c
    ${PATH_SECURE_CORE}/Src/se_nv.c
    ${PATH_SECURE_CORE}/Src/se_cert_spki.c
    ${PATH_SECURE_CORE}/Src/se_tls_user.c
    ${PATH_SECURE_CORE}/Src/secure_qkd_ingest.c
    ${PATH_SECURE_CORE}/Src/secure_otp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/port_posix.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test_harness.c
    ${CMAKE_CURRENT_SOURCE_DIR}/host_fw_mlkem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sae_qkd.c
)

add_library(se_tropic_host STATIC ${SE_TROPIC_RUNTIME})
target_include_directories(se_tropic_host PUBLIC
    ${PATH_SECURE_CORE}/Inc
    ${PATH_LIBTROPIC}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(se_tropic_host PUBLIC
    SE_TROPIC_SH0_PROD
    WOLFSSL_NO_OPTIONS_H
    WOLFSSL_HAVE_MLKEM
    WOLFSSL_WC_MLKEM
    WOLFSSL_HAVE_MLDSA
    HAVE_DILITHIUM
    WOLFSSL_WC_DILITHIUM
    HAVE_KEYING_MATERIAL
    WOLFSSL_SHA3
)
# Host uses prod0 SH0 via host_libtropic_config.h (not firmware eng_sample defaults)
target_compile_options(se_tropic_host PUBLIC
    -include${CMAKE_CURRENT_SOURCE_DIR}/host_libtropic_config.h
)
target_link_libraries(se_tropic_host PUBLIC tropic)

###########################################################################
# Test executables + CTest via model_runner.py
###########################################################################
enable_testing()

function(add_model_test name src)
    add_executable(${name} ${src})
    target_link_libraries(${name} PRIVATE se_tropic_host)
    add_test(NAME ${name}
        COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/run_with_model.sh"
                "${CMAKE_CURRENT_BINARY_DIR}/${name}"
                "${MODEL_CFG_PATH}"
    )
    set_tests_properties(${name} PROPERTIES
        ENVIRONMENT "PATH=${MODEL_VENV}/bin:$ENV{PATH}"
        RUN_SERIAL TRUE
    )
endfunction()

add_model_test(test_a_session test_a_session.c)
add_model_test(test_b_ecc     test_b_ecc.c)
add_model_test(test_c_rmem    test_c_rmem.c)
add_model_test(test_d_pin     test_d_pin.c)
add_model_test(test_e_mcounter test_e_mcounter.c)
add_model_test(test_f_mlkem   test_f_mlkem.c)
add_model_test(test_g_ingest  test_g_ingest.c)
add_model_test(test_h_pairing test_h_pairing.c)
add_model_test(test_i_post_tls test_i_post_tls.c)
add_model_test(brick_lab      brick_lab.c)

# Integration runner against a live JAVA_TLS_TEST Node (not a default CTest).
add_executable(se_host
    se_host_main.c
    se_host_tls.c
    ${PATH_SECURE_CORE}/Src/secure_client_key.c
    ${PATH_SECURE_CORE}/Src/secure_wrap.c
)
target_link_libraries(se_host PRIVATE se_tropic_host)

# brick_lab mutates irreversible state; run last and do not parallelize with others
set_tests_properties(brick_lab PROPERTIES
    RUN_SERIAL TRUE
)

# Firmware nm gate (optional: pass -DFIRMWARE_ELF=... when Secure.elf exists)
set(FIRMWARE_ELF "" CACHE FILEPATH "Path to SE_firmware_Secure.elf for nm brick-API gate")
if(FIRMWARE_ELF AND EXISTS "${FIRMWARE_ELF}")
    add_test(NAME firmware_nm_gate
        COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/check_firmware_nm.sh" "${FIRMWARE_ELF}"
    )
endif()
