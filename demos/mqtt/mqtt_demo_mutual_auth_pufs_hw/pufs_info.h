/***********************************************************************************
 *
 *  Copyright (c) 2022-2024, PUFsecurity
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
 *@file        pufs_info.h
 *
 *@brief       The header file implments PUFsecurity get information functions
 *
 *@copyright   2022-2024 PUFsecurity
 *
 ***************************************************************************************/


#ifndef __PUF_INFO_H__
#define __PUF_INFO_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


/*****************************************************************************
 * Enumerations
 ****************************************************************************/


/*****************************************************************************
 * Structure definition
 ****************************************************************************/

/*****************************************************************************
 * API functions
 ****************************************************************************/


/*****************************************************************************
 * Function Declaration
 ****************************************************************************/
long double Getcpu();
long double GetProcessMemory();
int parseLine(char *line);
void Getcurrenttime(char *t);
void Gethealthreport_json(char *content);
void Gethealthreport_flatten(char *content);
void GenerateExample_Payload(char *base_msg, uint32_t len, char *content, uint32_t idx);

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* __PUF_INFO_H__ */
