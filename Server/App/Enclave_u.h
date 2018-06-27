#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t enclave_aes_key(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* enc_aes_key, int size);
sgx_status_t enclave_aes_encrypt(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, uint8_t* mac_buffer);
sgx_status_t enclave_aes_decrypt(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, const uint8_t* mac_buffer);
sgx_status_t enclave_ra_build_msg2(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* g_a, sgx_ra_msg2_t* msg2_raw, uint32_t msg2_len, const uint8_t* sig_rl, uint32_t sig_rl_size, uint8_t* spid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
