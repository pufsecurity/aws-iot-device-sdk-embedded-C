/***********************************************************************************
 *
 *  Copyright (c) 2023-2024, PUFsecurity
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  3. Neither the name of PUFsecurity nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 *  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************************/


/*!*************************************************************************************
 *
 *@file        pufs_util_log.h
 *
 *@brief       pufs_util log related define
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/


#ifndef __PUFS_UTIL_LOG_H__
#define __PUFS_UTIL_LOG_H__

#ifdef __cplusplus
extern "C" {
#endif


/*****************************************************************************
 * Define
 ****************************************************************************/

#define LOG_LEVEL_ERROR   1
#define LOG_LEVEL_WARN    2
#define LOG_LEVEL_INFO    3
#define LOG_LEVEL_DEBUG   4
#define LOG_LEVEL_TRACE   5


#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

#define PRINT(...) printf(__VA_ARGS__)
#define PUFS_LOG_PRINT(level, str, ...) PRINT("[%s] %s(): " str "\n", level, __func__, ## __VA_ARGS__)


#if LOG_LEVEL >= LOG_LEVEL_TRACE
#define PUFS_LOG_TRACE(...) PUFS_LOG_PRINT("TRACE", __VA_ARGS__)
#else
#define PUFS_LOG_TRACE(...) {}
#endif


#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define PUFS_LOG_DEBUG(...) PUFS_LOG_PRINT("DEBUG", __VA_ARGS__)
#else
#define PUFS_LOG_DEBUG(...) {}
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define PUFS_LOG_INFO(...) PUFS_LOG_PRINT("INFO", __VA_ARGS__)
#else
#define PUFS_LOG_INFO(...) {}
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#define PUFS_LOG_WARN(...) PUFS_LOG_PRINT("WARN", __VA_ARGS__)
#else
#define PUFS_LOG_WARN(...) {}
#endif

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define PUFS_LOG_ERR(...) PUFS_LOG_PRINT("ERROR", __VA_ARGS__)
#else
#define PUFS_LOG_ERR(...) {}
#endif


#define PUFS_LOG_FUNC(...)          printf("%s\n", __func__)



#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* __PUFS_UTIL_LOG_H__ */
