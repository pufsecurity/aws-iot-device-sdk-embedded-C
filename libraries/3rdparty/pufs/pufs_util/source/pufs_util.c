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
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ¡§AS IS¡¨ AND
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
 *@file        pufs_util.c
 *
 *@brief       pufs_util main function
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/


#include <stdio.h>
#include <string.h>
#include <stdint.h>


#include "pufs_util_common.h"




/*****************************************************************************/
/**
 * @fn    bin_to_hex
 * @brief binary to hex string
 *
 * @param[out] buf_hex       Pointer of buffer for output hex string
 * @param[in]  size_hex      Prepared buffer size for hex string
 * @param[in]  buf_bin       Pointer of buffer for input binary buffer
 * @param[in]  size_bin      binary data size prepared to convert. (max : 0x7FFFFFFF)
 * @return     the number of characters written to buf_hex.
 *
 ****************************************************************************/

uint32_t bin_to_hex(uint8_t *buf_hex, uint32_t size_hex, uint8_t *buf_bin, uint32_t size_bin)
{

    uint8_t *ptr_hex;
    uint8_t *ptr_bin;
    uint32_t i, count;
    unsigned char  hex_str[] = "0123456789abcdef";

    //if (size_bin > ((size_hex -1) >> 1))
    if (size_bin > (size_hex >> 1))
    {
        PUFS_LOG_ERR("In sufficient size_hex (0x%x) !! size_bin (0x%x) \n", size_hex, size_bin);
        return 0;
    }

    if ((size_bin == 0) || (size_hex == 0))
    {
        PUFS_LOG_ERR("0 buffer size !! size_hex (0x%x), size_bin (0x%x) \n", size_hex, size_bin);
        return 0;
    }

    ptr_hex = buf_hex;
    ptr_bin = buf_bin;
    count = 0;

    for (i = 0 ; i < size_bin; i++, ptr_bin++, ptr_hex += 2, count += 2)
    {
        *ptr_hex     = hex_str[((*ptr_bin) >> 4) & 0x0F];
        *(ptr_hex + 1) = hex_str[ (*ptr_bin)     & 0x0F];
    }

    //end
    //*ptr_hex = 0;
    //count++;
    return count;

}

/*****************************************************************************/
/**
 * @fn    hexchar_to_int
 * @brief hex char to integer
 *
 * @param[in]  c      input char prepared to convert to hex value
 * @return     converted hex value
 *
 ****************************************************************************/

uint8_t hexchar_to_int(char c)
{
    switch (c)
    {
        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;
        case 'a':
        case 'A':
            return 0x0A;
        case 'b':
        case 'B':
            return 0x0B;
        case 'c':
        case 'C':
            return 0x0C;
        case 'd':
        case 'D':
            return 0x0D;
        case 'e':
        case 'E':
            return 0x0E;
        case 'f':
        case 'F':
            return 0x0F;
    }
    return 0xFF;
}

/*****************************************************************************/
/**
 * @fn    hex_to_bin
 * @brief hex string to binary
 *
 * @param[out] buf_bin       Pointer of buffer for binary data
 * @param[in]  size_bin      Prepared buffer size for binary data
 * @param[in]  buf_hex       Pointer of buffer for input binary buffer
 * @param[in]  size_hex      size of hex string prepared to convert. (max : 0xFFFFFFFE)
 * @return     the number of characters written to buf_bin.
 *
 ****************************************************************************/
uint32_t hex_to_bin(uint8_t *buf_bin, uint32_t size_bin, uint8_t *buf_hex, uint32_t size_hex)
{

    uint8_t *ptr_hex;
    uint8_t *ptr_bin;
    uint32_t i, count;
    //int hex = 0;
    uint8_t byte_high = 0;
    uint8_t byte_low = 0;

    if (size_bin < (size_hex >> 1))
    {
        PUFS_LOG_ERR("In sufficient size_bin (0x%x) !! size_hex (0x%x) \n", size_bin, size_hex);
        return 0;
    }

    if ((size_hex % 2) != 0)
    {
        PUFS_LOG_ERR("Incorrect hex string size - size_hex (0x%x) not even !! \n", size_hex);
        return 0;
    }

    if ((size_bin == 0) || (size_hex == 0))
    {
        PUFS_LOG_ERR("0 buffer size !! size_bin (0x%x), size_hex(0x%x) \n", size_bin, size_hex);
        return 0;
    }

    ptr_hex = buf_hex;
    ptr_bin = buf_bin;
    count = 0;

    for (i = 0 ; i < size_hex / 2; i++, ptr_bin++, ptr_hex += 2, count++)
    {
        byte_high  = hexchar_to_int((*ptr_hex));
        byte_low  = hexchar_to_int(*(ptr_hex + 1));

        if (byte_high == 0xFF || byte_low == 0xFF)
        {
            PUFS_LOG_ERR("0 Incorrect input charater, i:%d, hex_buf[i]:%c, hex_buf[i+1]:%c \n",
                         i, *ptr_hex, *(ptr_hex + 1));
            return 0;
        }
        *ptr_bin  = ((byte_high & 0x0F) << 4) | (byte_low & 0x0F);

    }

    //end
    //*ptr_hex = 0;
    //count++;
    return count;

}


/*****************************************************************************/
/**
 * @fn    print_value
 * @brief print values of an array
 *
 * @param[in]  ptr_to_print  Pointer of data prepared to print
 * @param[in]  size          size of data.
 * @return  void
 *
 ****************************************************************************/

void print_value(uint8_t     *ptr_to_print, uint32_t size)
{
    uint32_t i;
    uint8_t *tmpPtr = ptr_to_print;
    for (i = 0; i < size; i++, tmpPtr++)
    {
        printf("0x%02x ", *tmpPtr);
        if ((i % 16) == 15)
        {
            printf("\n");
        }
    }
    printf("\n");
}
