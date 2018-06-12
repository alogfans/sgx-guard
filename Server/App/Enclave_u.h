#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_key_exchange.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t SetAesKey(sgx_enclave_id_t eid, int* retval, const uint8_t* aes_key, int size);
sgx_status_t GetAesKey(sgx_enclave_id_t eid, int* retval, uint8_t* aes_key, int size);
sgx_status_t EnclaveAesEncryption(sgx_enclave_id_t eid, int* retval, const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, uint8_t* mac_buffer);
sgx_status_t EnclaveAesDecryption(sgx_enclave_id_t eid, int* retval, const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, const uint8_t* mac_buffer);
sgx_status_t enclave_build_msg1(sgx_enclave_id_t eid, int* retval, sgx_ec256_public_t* g_a, sgx_ec256_public_t* g_b, sgx_ec256_signature_t* sign_gb_ga, sgx_cmac_128bit_tag_t* mac);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
