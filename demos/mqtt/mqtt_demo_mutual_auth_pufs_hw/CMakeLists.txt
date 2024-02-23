set( DEMO_NAME "mqtt_demo_mutual_auth_pufs_hw" )

# Include MQTT library's source and header path variables.
include( ${CMAKE_SOURCE_DIR}/libraries/standard/coreMQTT/mqttFilePaths.cmake )

# Include backoffAlgorithm library file path configuration.
include( ${CMAKE_SOURCE_DIR}/libraries/standard/backoffAlgorithm/backoffAlgorithmFilePaths.cmake )

# PUFS +++
if (PUFS_HW_CRYPTO)
    # Add pufs_util libary
    include ( ${3RDPARTY_DIR}/pufs/pufs_util/pufsUtilFilePaths.cmake )
endif()
# PUFS ---

# CPP files are searched for supporting CI build checks that verify C++ linkage of the coreMQTT library
file( GLOB DEMO_FILE "${DEMO_NAME}.c*" )
if (PUFS_HW_CRYPTO)
    file( GLOB PUFS_DEMO_SRCS "pufs_*.c*" )
    message("PUFS_DEMO_SRCS ${PUFS_DEMO_SRCS}")
endif()

# Demo target.
# PUFS +++
if (PUFS_HW_CRYPTO)
    add_executable(
        ${DEMO_NAME}
            "${DEMO_FILE}"
            ${PUFS_DEMO_SRCS}
            ${MQTT_SOURCES}
            ${MQTT_SERIALIZER_SOURCES}
            ${BACKOFF_ALGORITHM_SOURCES}
            ${PUFS_UTIL_SOURCES}
    )

    if (PUFSE_HOST)
       if (GCC_ARM)
           target_link_libraries(
                ${DEMO_NAME} PRIVATE
                    mbedtls
                    clock_posix
                    transport_pufs_hw_mbedtls_posix
                    pufse_host
                    udev_arm

            )
        else()

            target_link_libraries(
                ${DEMO_NAME} PRIVATE
                    mbedtls
                    clock_posix
                    transport_pufs_hw_mbedtls_posix
                    pufse_host
            )
        endif(GCC_ARM)

    else()

        target_link_libraries(
            ${DEMO_NAME} PRIVATE
                mbedtls
                clock_posix
                transport_pufs_hw_mbedtls_posix
                pufcc
        )

    endif(PUFSE_HOST)

else ()
# PUFS ---
add_executable(
    ${DEMO_NAME}
        "${DEMO_FILE}"
        ${MQTT_SOURCES}
        ${MQTT_SERIALIZER_SOURCES}
        ${BACKOFF_ALGORITHM_SOURCES}
)


target_link_libraries(
    ${DEMO_NAME} PRIVATE
      mbedtls
      clock_posix
      transport_pufs_hw_mbedtls_posix )
# PUFS +++
endif()
# PUFS ---

set (USE_PUFS_ROOT_CA ON)

if (USE_PUFS_ROOT_CA)
    message("Use device signed by pufsecurity root ca ")
    add_definitions(-DPUFS_ROOT_CA)
endif()




if (PUFS_HW_CRYPTO)
    if (PUFSE_HOST)
        target_include_directories(
            ${DEMO_NAME}
            PUBLIC
                ${MQTT_INCLUDE_PUBLIC_DIRS}
                ${BACKOFF_ALGORITHM_INCLUDE_PUBLIC_DIRS}
                ${LOGGING_INCLUDE_DIRS}
                ${AWS_DEMO_INCLUDE_DIRS}
                ${CMAKE_CURRENT_LIST_DIR}
                ${PUFS_UTIL_INCLUDE_PUBLIC_DIRS}
                ${PUFS_HW_CRYPTO_INCLUDE_DIRS}
        )
    else()
        target_include_directories(
            ${DEMO_NAME}
            PUBLIC
                ${MQTT_INCLUDE_PUBLIC_DIRS}
                ${BACKOFF_ALGORITHM_INCLUDE_PUBLIC_DIRS}
                ${LOGGING_INCLUDE_DIRS}
                ${AWS_DEMO_INCLUDE_DIRS}
                ${CMAKE_CURRENT_LIST_DIR}
                ${PUFS_UTIL_INCLUDE_PUBLIC_DIRS}
                ${PUFS_HW_CRYPTO_INCLUDE_DIRS}
        )
    endif()
else ()
target_include_directories(
    ${DEMO_NAME}
    PUBLIC
        ${MQTT_INCLUDE_PUBLIC_DIRS}
        ${BACKOFF_ALGORITHM_INCLUDE_PUBLIC_DIRS}
        ${LOGGING_INCLUDE_DIRS}
        ${AWS_DEMO_INCLUDE_DIRS}
        ${CMAKE_CURRENT_LIST_DIR}
)
endif()

# Copy run.sh
if (PUFS_MODIFY)
    file(COPY "run.sh"
         DESTINATION ${CMAKE_BINARY_DIR}/bin)

    file(COPY "env.sh"
         DESTINATION ${CMAKE_BINARY_DIR}/bin)

    file(COPY "read_info.sh"
         DESTINATION ${CMAKE_BINARY_DIR}/bin)

endif()

set_macro_definitions(TARGETS ${DEMO_NAME}
                      REQUIRED
                        "AWS_IOT_ENDPOINT"
                        "ROOT_CA_CERT_PATH"
                        "CLIENT_CERT_PATH"
                        "CLIENT_PRIVATE_KEY_PATH"
                        "CLIENT_IDENTIFIER"
                      OPTIONAL
                        "CLIENT_USERNAME"
                        "CLIENT_PASSWORD"
                        "OS_NAME"
                        "OS_VERSION"
                        "HARDWARE_PLATFORM_NAME")
