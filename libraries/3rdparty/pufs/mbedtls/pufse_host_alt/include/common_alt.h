/*
 * Copyright (c) 2023-2024, PUFsecurity. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COMMON_ALT_H
#define COMMON_ALT_H

#include <stdio.h>


#include "pufs_util_log.h"

#ifdef MBEDTLS_CONFIG_FILE
#include MBEDTLS_CONFIG_FILE
#endif

#define MBEDTLS_ERR_PUFS_HW_ACCEL_FAILED   -0x0037 /**< PUFS Crypto hardware accelerator failed */



//#define LOG_WRAP_INFO  //If wapper info log enabled

#if LOG_LEVEL <= LOG_LEVEL_INFO
#define PUFS_LOG_INF(...)     PUFS_LOG_PRINT("INF", __VA_ARGS__)
#else
#define PUFS_LOG_INF(...)
#endif



#ifdef LOG_WRAP_INFO
#define PUFS_LOG_WRAP_FUNC(...)    PUFS_LOG_INF(__VA_ARGS__)
#else
#define PUFS_LOG_WRAP_FUNC(...)
#endif

#ifdef PUFS_LOG_FUNC
#undef PUFS_LOG_FUNC
#warning ("redefine PUFS_LOG_FUNC");

#if (DEMO_LOG_LEVEL == 0)
//   #define PUFS_LOG_FUNC(...)   {}
   #define FUNC_LOG_PRIFIX      "      "
   #define PUFS_LOG_FUNC(...)   PRINT(FUNC_LOG_PRIFIX); PRINT("%s", ## __VA_ARGS__);
#else
   #define PUFS_LOG_FUNC(...)   PRINT("%s", ## __VA_ARGS__)
#endif

#endif /* PUFS_LOG_FUNC */

#define PUFS_INFO_RET(...) \
    do { \
        LOG_INFO(__VA_ARGS__); \
        return 0; \
    } while (0)

#define PUFS_ERR_RET(...) \
    do { \
        LOG_ERROR(__VA_ARGS__); \
        return MBEDTLS_ERR_PUFS_HW_ACCEL_FAILED; \
    } while (0)

#define PUFS_CALL_ERR(ret, func, ...) \
    do { \
        if ((ret = func(__VA_ARGS__)) != SUCCESS) \
            PUFS_ERR_RET("%s: %d", #func, ret); \
    } while (0)

#define PUFS_CALL_WARN(ret, func, ...) \
    do { \
        if ((ret = func(__VA_ARGS__)) != SUCCESS) \
            LOG_WARN("%s: %d", #func, ret); \
    } while (0)


//For unused variable compile warning
#define PUFS_MBEDTLS_UNUSED(x) (void)(x)

#endif /* COMMON_ALT_H */
