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
 *@file        pufs_util_sec.c
 *
 *@brief       pufs_util secure module related function
 *
 *@copyright   2023-2024 PUFsecurity
 *
 ***************************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>  //malloc, free calloc

#ifdef PUFSE_HOST

//#include "pufs_basic.h"
#include "pufs_pkc.h"
#include "pufs_drbg.h"  //pufs_sp90a.h

#else

#include "pufs_memory_map.h"
#include "pufs_common.h"
#include "pufs_ecp.h"
#include "pufs_crypto.h"
#include "pufs_dma.h"
#include "pufs_sp90a.h"
#include "pufs_rt_internal.h"  //for rt_check_enrolled
#include "pufs_ka_internal.h" //for keyslot_check

#endif /* PUFSE_HOST */

#include "pufs_sp38a.h"
#include "pufs_sp38c.h"
#include "pufs_sp38d.h"
#include "pufs_sp38e.h"
#include "pufs_cmac.h"
#include "pufs_kdf.h"
#include "pufs_rt.h"

//#include "pufs_log.h"

#include "pufs_util_sec.h"





/*****************************************************************************
 * Define
 ****************************************************************************/
//Used Key slot define
//PUF_SLOT
#define UID_SLOT                     PUFSLOT_0
#define PUF_SLOT_FOR_DEV_KEY_GEN     PUFSLOT_1   //Slot used for device static private key generation
#define PUF_SLOT_FOR_KEK_GEN         PUFSLOT_2   //Slot used for wrap key generation (KDK)

//PRK_SLOT
#define PRK_SLOT_FOR_DEV            PRK_0       //Private Key slot for device key generation
#define PRK_SLOT_FOR_IMPORT         PRK_1       //Private key slot to import the generated private key


//SK_SLOT
#define KEK_KEY_SLOT                 SK256_1


// Key Length
#define PRIV_KEY_LEN             (32*8)       //in bits
#define KDK_LEN                  (32*8)       //in bits
#define KEK_LEN                  (32*8)       //in bits
#define WRAP_KEY_LEN             (32*8)       //in bits

//Key slot information bit
#define KEY_VALID_BITMASK        0x00000001 //BIT 0,
#define KEY_VALID_FLAG           0x01UL     // 0: null

#define KEY_ORIGIN_BITMASK       0x0000000E //BIT [3:1]
#define KEY_LEN_BITMASK          0x00007FF0 //BIT [14:4]
#define KEY_LEN_BIT_SHIFT        0x04 //BIT [14:4]


/*****************************************************************************
 * Macro Define
 ****************************************************************************/
#define GET_PRIV_KEY_SLOT_IDX(slot) \
    (((slot >=PRK_0) && (slot <= PRK_2))? (slot-PRK_0) : (0xFE))

#define GET_SK256_KEY_SLOT_IDX(slot) \
    (((slot >=SK256_0) && (slot <= SK256_3))? ((slot-SK256_0)<<1) : (0xFE))

#define GET_SK128_KEY_SLOT_IDX(slot) \
    (((slot >=SK128_0) && (slot <= SK128_7))? ((slot-SK128_0)<<1) : (0xFE))



#ifdef SIGN_CMD_SUPPORT
#define PUFS_CHECK_DEBUG_FORMAT(cnd, fmt, ...) \
  if ((cnd)) {                                 \
    PUFS_LOG_ERR(fmt, __VA_ARGS__);            \
    rt = PUFS_FAIL;                            \
    goto exit;                                 \
  }
#endif


/*****************************************************************************
 * Variable Define
 ****************************************************************************/
extern struct pufs_rt_regs *rt_regs;
extern void print_value(uint8_t     *ptr_to_print, uint32_t size);

/**
 * @fn    giot_init_pufs_sec_module_init
 * @brief pufsecurity module initilization
 * @return  PUFS_SUCCESS or PUFS_FAIL
 */
rt_status_t pufs_util_sec_module_init()
{
#ifdef PUFSE_HOST
    pufs_status_t status;

    /* PUFse cmd interface init */
    status = pufs_cmd_iface_init();
    if (status != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_cmd_iface_init fail error:%d\n", status);
        return PUFS_FAIL;
    }
#else
    PUFS_LOG_INFO("PUFIOT_ADDR_START:0x%x PUFIOT_MAP_SIZE:%d\n", PUFIOT_ADDR_START, PUFIOT_MAP_SIZE );

    pufs_module_init(PUFIOT_ADDR_START, PUFIOT_MAP_SIZE);
    pufs_dma_module_init(DMA_ADDR_OFFSET);
    pufs_rt_module_init(RT_ADDR_OFFSET);
    pufs_ka_module_init(KA_ADDR_OFFSET);
    pufs_kwp_module_init(KWP_ADDR_OFFSET);
    pufs_crypto_module_init(CRYPTO_ADDR_OFFSET);
    pufs_hmac_module_init(HMAC_HASH_ADDR_OFFSET);
    pufs_sp38a_module_init(SP38A_ADDR_OFFSET);
    pufs_sp38c_module_init(SP38C_ADDR_OFFSET);
    pufs_sp38d_module_init(SP38D_ADDR_OFFSET);
    pufs_sp38e_module_init(SP38E_ADDR_OFFSET);
    pufs_cmac_module_init(CMAC_ADDR_OFFSET);
    pufs_kdf_module_init(KDF_ADDR_OFFSET);
    pufs_pkc_module_init(PKC_ADDR_OFFSET);
    pufs_drbg_module_init(SP90A_ADDR_OFFSET);
#endif
    return PUFS_SUCCESS;

}


/**
 * @fn    pufs_util_sec_module_release
 * @brief pufsecurity module release
 * @return  PUFS_SUCCESS or PUFS_FAIL
 */
rt_status_t pufs_util_sec_module_release()
{

#ifdef PUFSE_HOST
    pufs_status_t status;

    /* PUFse cmd interface init */
    status = pufs_cmd_iface_deinit();
    if (status != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_cmd_iface_deinit fail error:%d\n", status);
        return PUFS_FAIL;
    }
#else
    pufs_release();
#endif
    return PUFS_SUCCESS;

}



/**
 * @fn    pufs_util_sec_read_uid_puf
 * @brief Read uid and puf otp
 */

void pufs_util_sec_read_uid_puf()
{
    uint32_t index;
    pufs_uid_st uid;
    pufs_status_t status = SUCCESS;


    memset(&uid, 0, sizeof(pufs_uid_st));

    printf("Read UID ----------------- \n");

    status = pufs_get_uid(&uid, PUFSLOT_0);

    if (status != SUCCESS)
    {
        printf("get uid failed err:%d\n", status);
        return ;
    }

    print_value(uid.uid, sizeof(uid.uid));

    printf("Read PUF ----------------- \n");

    for (index = PUFSLOT_1; index <= PUFSLOT_3; index++ )
    {
        status = pufs_get_uid(&uid, index);

        if (status != SUCCESS)
        {
            printf("get puf slot:%d failed err:%d\n", index, status);
            return ;
        }

        printf("PUF slot %d \n", index);
        print_value(uid.uid, sizeof(uid.uid));
    }

}


/**
 * @fn    pufs_util_sec_enroll_puf
 * @brief check puf enroll status and enroll puf if puf has not been enrolled.
 *
 */

void pufs_util_sec_enroll_puf(void)
{
#ifdef PUFSE_HOST
    PUFS_LOG_INFO("pufse host utility !! don't need to enroll puf\n");
#else
    if (rt_check_enrolled())
    {
        PUFS_LOG_INFO("puf has enrolled !! Skip!!\n");
        return;
    }

    rt_write_enroll();
    PUFS_LOG_INFO("Enroll PUF!!\n");
#endif
}

/**
 * @fn          pufs_util_sec_gen_ecdsa_key
 * @brief
 * @param[in]   algo        algorithm to generate key.
 * @param[out]  p_kprv_slot Pointer to generated private key slot
 *                          (valid : PRK_0 - PRK_3, 0xFF(invalid)
 *
 * @param[out]  p_kpub      Pointer to generated ecdsa public key structure

 * @return  PUFS_SUCCESS, PUFS_FAIL
 *
 */
rt_status_t pufs_util_sec_gen_ecdsa_key(pufs_util_sec_key_algo_t algo, uint8_t *p_kprv_slot, pufs_ec_point_st *p_kpub)
{

    pufs_status_t check = SUCCESS;
    pufs_ka_slot_t dev_prk_slot = PRK_SLOT_FOR_DEV;
    pufs_rt_slot_t puf_slot = PUF_SLOT_FOR_DEV_KEY_GEN;  //PUFSLOT_1
    const char *salt = "pufsecurity salt";
    pufs_uid_st uid;

    PUFS_LOG_FUNC();

    if (algo != SEC_KEY_ECDSAP256)
    {
        PUFS_LOG_ERR("Unsupported key generation algorithm, %d\n", algo);
        return PUFS_FAIL;
    }

    if (p_kprv_slot ==  NULL)
    {
        PUFS_LOG_ERR("Null private key slot\n");
        return PUFS_FAIL;
    }

    if (p_kpub ==  NULL)
    {
        PUFS_LOG_ERR("Null public key slot\n");
        return PUFS_FAIL;
    }


    *p_kprv_slot = 0xFF;

    //1. Generate Private Key
    pufs_ecp_set_curve_byname(NISTP256);

    memset(&uid, 0, sizeof(uid));

    pufs_get_uid(&uid, UID_SLOT);
    check = pufs_ecp_gen_sprk(dev_prk_slot, puf_slot, (uint8_t *)salt, 16, (uint8_t *)uid.uid, UIDLEN, SHA_256);

    if (check != SUCCESS)
    {
        PUFS_LOG_ERR("Private key generation failed (err:%d) !!\n", check);
        return PUFS_FAIL;
    }

    //2. Generate Public Key
    check = pufs_ecp_gen_puk(p_kpub, PRKEY, dev_prk_slot);

    if (check != SUCCESS)
    {
        PUFS_LOG_ERR("Public key generation failed (err:%d) !!\n", check);

        //clear generate private key
        check = pufs_clear_key(PRKEY, dev_prk_slot, PRIV_KEY_LEN);
        if (check != SUCCESS)
        {
            PUFS_LOG_ERR("Clear private key slot (%d) generation failed (err:%d) !!\n", dev_prk_slot, check);
        }
        return PUFS_FAIL;
    }

#ifdef PRINT_PUB_KEY
    printf("puk_k len:%d \n", p_kpub->qlen);
    printf("x :\n");
    print_value((uint8_t *)(&(p_kpub->x)), p_kpub->qlen);
    printf("y :\n");
    print_value((uint8_t *)(&(p_kpub->y)), p_kpub->qlen);
#endif

    *p_kprv_slot = dev_prk_slot;
    return PUFS_SUCCESS;

}


/**
 * @fn    pufs_util_sec_export_wrapped_priv_key
 * @brief
 * @param[in]  p_kprv_slot       Pointer to private key slot prepared to export

 * @return  PUFS_SUCCESS, PUFS_FAIL
 *
 */
rt_status_t pufs_util_sec_export_wrapped_priv_key(uint8_t *p_kprv_slot, uint8_t *out, uint32_t size)
{
    pufs_status_t check = SUCCESS;
    rt_status_t rt_status = PUFS_SUCCESS;
    pufs_key_wrap_t kwp_wrap_type = AES_KWP;
    pufs_key_type_t kdk_type = PUFKEY;
    pufs_rt_slot_t  kdk_puf_slot = PUF_SLOT_FOR_KEK_GEN;
    pufs_ka_slot_t  kek_key_slot = KEK_KEY_SLOT;
    uint32_t keybits = size * 8;

    if (keybits < WRAP_KEY_LEN)
    {
        PUFS_LOG_ERR("insufficient size %d (min size :%d)\n", size, WRAP_KEY_LEN);
    }

    if ((out == NULL) || (p_kprv_slot == NULL))
    {
        PUFS_LOG_ERR("Null pointer (out:0x%lx, p_kprv_slot:0x%lx) \n", (unsigned long)out, (unsigned long) p_kprv_slot);
    }

    //kdktype and kdkaddr is input for Z. see (_pufs_kdf_base)
    check = pufs_key_expansion(SSKEY, kek_key_slot, KEK_LEN, PRF_HMAC, SHA_256, false,
                               NULL, 0, 4, kdk_type, kdk_puf_slot, KDK_LEN, NULL, 0);

    if (check != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_key_expanssion failed (err:%d)\n", check);
        return PUFS_FAIL;
    }

    check = pufs_export_wrapped_key(PRKEY, *p_kprv_slot, out, keybits, kek_key_slot, KEK_LEN, kwp_wrap_type, NULL);

    if (check != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_export_wrapped_key failed (err:%d)\n", check);

        rt_status = PUFS_FAIL;
    }
#ifdef UTIL_DEBUG_BUF_PRINT
    else
    {
        printf("wrapped key: keybits:%d out addr:0x%x\n", keybits, (uint32_t) out);
        //print_value(out, keybits/8);
        print_value(out, keybits / 8 + 8);
    }
#endif

    return rt_status;

}


/**
 * @fn    pufs_util_sec_import_wrapped_priv_key_test
 * @brief Import wrapped private key test.
 *        This function will import wrapped key and output the generated public key
 * @param[in]  wrapped_key       Pointer to input wrapped key
 *                               (key buffer size is about 8 bytes larger than key_szie)
 * @param[in]  key_size          Size of input wrapped key (byte)
 * @return  PUFS_SUCCESS, PUFS_FAIL
 *
 */
rt_status_t pufs_util_sec_import_wrapped_priv_key_test(uint8_t *wrapped_key, uint32_t key_size)
{
    pufs_status_t check = SUCCESS;
    pufs_key_wrap_t kwp_wrap_type = AES_KWP;
    pufs_ec_point_st kpub;
    pufs_ka_slot_t import_prk_slot = PRK_SLOT_FOR_IMPORT;
    pufs_ka_slot_t kek_key_slot = KEK_KEY_SLOT;
    uint32_t keybits = key_size * 8;

    check = pufs_import_wrapped_key(PRKEY, import_prk_slot, wrapped_key, keybits, kek_key_slot, KEK_LEN, kwp_wrap_type,
                                    NULL);
    if (check != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_import_wrapped_key failed!  (err:%d)\n", check);
    }

    // Generate public key
    pufs_ecp_set_curve_byname(NISTP256);

    check = pufs_ecp_gen_puk(&kpub, PRKEY, import_prk_slot);
    if (check != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_ecp_gen_puk failed :%d\n", check);
        return PUFS_FAIL;
    }

#ifdef UTIL_DEBUG_BUF_PRINT
    printf("puk2_k len:%d\n", kpub.qlen);
    printf("x :\n");
    print_value((uint8_t *)(&(kpub.x)), kpub.qlen);
    printf("y :\n");
    print_value((uint8_t *)(&(kpub.y)), kpub.qlen);
#endif

    return PUFS_SUCCESS;

}


/**
 * @fn    pufs_util_sec_clear_used_key_slot
 * @brief Clear used key slot during import/export comand/test
 * @return  PUFS_SUCCESS
 *
 */

rt_status_t pufs_util_sec_clear_used_key_slot()
{
    pufs_status_t check = SUCCESS;
    pufs_ka_slot_t key_slot;

#ifdef PUFSE_HOST
    // generated private key for device
    key_slot = PRK_SLOT_FOR_DEV;
    check = pufs_clear_key(PRKEY, key_slot, PRIV_KEY_LEN);
    if (check != SUCCESS)
    {
        PUFS_LOG_INFO("Private key slot %d clear failed (err:%d) !!\n", key_slot, check);
    }

    //session key for key encryption key
    key_slot = KEK_KEY_SLOT;
    check = pufs_clear_key(SSKEY, key_slot, KEK_LEN);
    if (check != SUCCESS)
    {
        PUFS_LOG_INFO("KEK slot %d clear failed (err:%d) !!\n", key_slot, check);
    }

    //private key slot for import key
    key_slot = PRK_SLOT_FOR_IMPORT;
    check = pufs_clear_key(PRKEY, key_slot, PRIV_KEY_LEN);
    if (check != SUCCESS)
    {
        PUFS_LOG_INFO("Private key slot %d clear failed (err:%d) !!\n", key_slot, check);
    }

#else
    // generated private key for device
    key_slot = PRK_SLOT_FOR_DEV;
    check = keyslot_check(true, PRKEY, key_slot, PRIV_KEY_LEN);
    if (check == SUCCESS)
    {
        check = pufs_clear_key(PRKEY, key_slot, PRIV_KEY_LEN);
        if (check != SUCCESS)
        {
            PUFS_LOG_ERR("Private key slot %d clear failed (err:%d) !!\n", key_slot, check);
        }
    }


    //session key for key encryption key
    key_slot = KEK_KEY_SLOT;
    check = keyslot_check(true, SSKEY, key_slot, KEK_LEN);
    if (check == SUCCESS)
    {
        check = pufs_clear_key(SSKEY, key_slot, KEK_LEN);
        if (check != SUCCESS)
        {
            PUFS_LOG_ERR("KEK slot %d clear failed (err:%d) !!\n", key_slot, check);
        }
    }

    //private key slot for import key
    key_slot = PRK_SLOT_FOR_IMPORT;
    check = keyslot_check(true, PRKEY, key_slot, PRIV_KEY_LEN);
    if (check == SUCCESS)
    {
        check = pufs_clear_key(PRKEY, key_slot, PRIV_KEY_LEN);
        if (check != SUCCESS)
        {
            PUFS_LOG_ERR("Private key slot %d clear failed (err:%d) !!\n", key_slot, check);
        }
    }
#endif

    return PUFS_SUCCESS;

}

#ifdef SIGN_CMD_SUPPORT
/**
 * @fn    pufs_util_sec_sha256
 * @brief
 * @param[out]  p_out_buf_32bytes  pointer to output buffer.
 * @param[in]   p_in_buf           pointer to input buffer.
 * @param[in]   in_buf_len         length of input buffer.
 *
 * @return  PUFS_SUCCESS, PUFS_FAIL
 *
 */
rt_status_t pufs_util_sec_sha256(uint8_t *p_out_buf_32bytes, uint8_t *p_in_buf, uint32_t in_buf_len)
{
    pufs_status_t check = SUCCESS;
    rt_status_t rt = PUFS_SUCCESS;
    pufs_dgst_st md;

    memset(&md, 0, sizeof(pufs_dgst_st));
    md.dlen = 32;

    if ((p_out_buf_32bytes == NULL) || (p_in_buf == NULL) || (in_buf_len == 0))
    {
        PUFS_LOG_ERR("HASH input parameter errors !\n");
        rt = PUFS_FAIL;
        goto exit;
    }

    if ((check = pufs_hash(&md, p_in_buf, in_buf_len, SHA_256)) != SUCCESS)
    {
        PUFS_LOG_ERR("HASH pufs_hash return failed [%d]\n", check);
        rt = PUFS_FAIL;
        goto exit;
    }

    memcpy(p_out_buf_32bytes, &(md.dgst), 32);

exit:
    return rt;

}


/**
 * @fn    pufs_util_sec_gen_ecdsa_sig
 * @brief Generates an Elliptic Curve signature for a private key slot.
 * @param[out]  p_sig       pointer to signature buffer.
 * @param[out]  p_sig_len   pointer to signature length.
 * @param[in]   algo        key generatation algorithm.
 * @param[in]   p_kprv_slot Pointer of the private key slot
 *                          (valid : PRK_0 - PRK_3, 0xFF(invalid)
 *
 * @return  PUFS_SUCCESS, PUFS_FAIL
 *
 */

rt_status_t pufs_util_sec_gen_ecdsa_sig(
    uint8_t *p_sig, uint32_t *p_sig_len,
    pufs_util_sec_key_algo_t algo, uint8_t *p_kprv_slot,
    uint8_t *p_md, uint32_t md_len)
{
    pufs_status_t rt = SUCCESS;
    pufs_ecdsa_sig_st sig;
    pufs_dgst_st md;
    uint8_t slot_id;

    if (NULL == p_kprv_slot || NULL == p_sig || NULL == p_sig_len ||
        NULL == p_md || md_len == 0 )
    {
        PUFS_LOG_ERR("generate siganature input parameter errors !\n");
        rt = PUFS_FAIL;
        goto exit;
    }

    if (SEC_KEY_ECDSAP256 != algo)
    {
        PUFS_LOG_ERR("generate siganature algorithm error:%d !\n", algo);
        rt = PUFS_FAIL;
        goto exit;
    }


    PUFS_CHECK_DEBUG_FORMAT(64 > *p_sig_len,
                            "siganature buffer must be >= %u: was %u", 64,
                            *p_sig_len);

    PUFS_CHECK_DEBUG_FORMAT(32 != md_len,
                            "md_len must be %u: was %u", 32,
                            md_len);

    memset(&md, 0, sizeof(pufs_dgst_st));
    memset(&sig, 0, sizeof(pufs_ecdsa_sig_st));

    //slot format : pufs_ka_slot_t (PRK_1)
    slot_id = *p_kprv_slot;
    md.dlen = md_len;
    memcpy(md.dgst, p_md, md_len);

    // input message is 32 bytes, output is 64 bytes
    // two 32 byte integers build up a JWT ECC signature: r and s
    // see https://tools.ietf.org/html/rfc7518#section-3.4
    // dst_buf : r (32 bytes) || s (32 bytes)
    rt = pufs_ecp_ecdsa_sign_dgst(&sig, md, PRKEY, slot_id, NULL);

    //PUFS_CHECK_DEBUG_FORMAT(SUCCESS != rt, "pufs_sign returned %d", rt);
    if (SUCCESS != rt)
    {
        PUFS_LOG_ERR("pufs_sign returned %d\n", rt);
        rt = PUFS_FAIL;
        goto exit;
    }

    memcpy(p_sig, sig.r, sig.qlen);
    memcpy(p_sig + sig.qlen, sig.s, sig.qlen);
    *p_sig_len = 2 * sig.qlen;
exit :
    return rt;

}
#endif


/*****************************************************************************/
/**
 * @fn    pufs_util_gen_sec_rn_bytes
 * @brief pufs_util module generate random number bytes
 *
 * @param[out]  p_out      Pointer to random number buffer.
 * @param[out]  p_len      Pointer to random number buffer length.
 * @param[out]  rn_len     length of random number bytes to be generated
 *
 * @return  PUFS_SUCCESS, PUFS_FAIL
 *
 ****************************************************************************/
rt_status_t pufs_util_sec_gen_rn_bytes(uint8_t *p_out, uint32_t *p_len, uint32_t rn_len)
{
    uint32_t blk = BYTE_TO_RNG_BLK(rn_len);
    //uint32_t size = 0;
    uint32_t size_tmp = 0;
    uint8_t  *p_randnum = NULL;
    rt_status_t  rt = PUFS_SUCCESS;

    PUFS_LOG_FUNC();

    if (*p_len < rn_len)
    {
        PUFS_LOG_ERR("insufficient output size :%d need:%d\n", *p_len, rn_len);
        rt = PUFS_FAIL;
        goto exit;
    }

    p_randnum = calloc((blk * RNG_BLK_SIZE_BYTE), sizeof(uint8_t));
    if (p_randnum == NULL)
    {
        PUFS_LOG_ERR("calloc for randnum buffer failed \n");
        rt = PUFS_FAIL;
        goto exit;
    }

    if (pufs_rand(p_randnum, blk) != SUCCESS)
    {
        PUFS_LOG_ERR("pufs_rand() for blk:%d, bits:%d failed \n", blk, rn_len);
        rt = PUFS_FAIL;
        goto exit;
    }

    PUFS_LOG_INFO("rn_len = %d \n", rn_len);

    if ((rn_len % RNG_BLK_SIZE_BYTE) != 0)
    {
        size_tmp = (blk - 1) * RNG_BLK_SIZE_BYTE;
        memcpy(p_out, p_randnum, size_tmp);
        memcpy(p_out + size_tmp, p_randnum + size_tmp, rn_len - size_tmp);
    }
    else
    {
        memcpy(p_out, p_randnum, rn_len);
    }

    *p_len = rn_len;

exit:
    if (p_randnum != NULL)
    {
        free(p_randnum);
    }

    return rt;

}
