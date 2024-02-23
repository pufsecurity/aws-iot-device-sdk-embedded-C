/**
 * @file      pufs_rt_cde.h
 * @brief     PUFsecurity PUFrt CDE API interface
 * @copyright 2022 PUFsecurity
 */
/* THIS SOFTWARE IS SUPPLIED BY PUFSECURITY ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. TO THE FULLEST
 * EXTENT ALLOWED BY LAW, PUFSECURITY'S TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES,
 * IF ANY, THAT YOU HAVE PAID DIRECTLY TO PUFSECURITY FOR THIS SOFTWARE.
 */

#ifndef __PUFS_RT_CDE_H__
#define __PUFS_RT_CDE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "pufs_common.h"
#include "pufs_rt.h"

/**
 * @brief Initialize PUFsrt CDE module
 *
 * @param[in] rt_cde_offset  PUFsrt cde offset of memory map
 */
pufs_status_t pufs_rt_cde_init(uint32_t rt_cde_offset);
/**
 * @brief Set CDE lock state
 *
 * @param[in] offset  Starting CDE address lock state to be set.
 * @param[in] length  The length of CDE data in bytes.
 * @param[in] lock    The lock state.
 * @return            SUCCESS on success, otherwise an error code.
 *
 * @note \em addr must be aligned to 4 bytes boundary
 */
pufs_status_t rt_cde_write_lock(uint32_t offset, uint32_t length, pufs_otp_lock_t lock);
/**
 * @brief Get CDE rwlck value
 *
 * @param[in] offset  The address of the rwlck.
 * @return            The rwlck bits.
 */
pufs_otp_lock_t rt_cde_read_lock(uint32_t offset);
/**
 * @brief PUFrt CDE post masking, mask 1K bits(128 bytes) segment starting from offset input
 *
 * @param[in] offset  Starting address of the segment to be masked
 * @return            SUCCESS on success, otherwise an error code.
 */
pufs_status_t rt_cde_write_mask(uint32_t offset);

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* __PUFS_RT_H__ */
