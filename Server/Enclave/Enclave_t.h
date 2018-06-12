#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_key_exchange.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int SetAesKey(const uint8_t* aes_key, int size);
int GetAesKey(uint8_t* aes_key, int size);
int EnclaveAesEncryption(const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, uint8_t* mac_buffer);
int EnclaveAesDecryption(const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, const uint8_t* mac_buffer);
int enclave_build_msg1(sgx_ec256_public_t* g_a, sgx_ec256_public_t* g_b, sgx_ec256_signature_t* sign_gb_ga, sgx_cmac_128bit_tag_t* mac);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
