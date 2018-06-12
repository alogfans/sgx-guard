#ifndef GUARD_ENCLAVE_H
#define GUARD_ENCLAVE_H

#include <stdlib.h>
#include <assert.h>
#include <sgx_key_exchange.h>

#if defined(__cplusplus)
extern "C" {
#endif
    // static sgx_aes_gcm_128bit_key_t aes_key = { 0 };
    static uint8_t sealed_aes_key[512] = { 0 };
    int SetAesKey(const uint8_t *aes_key, int size);
    int GetAesKey(uint8_t *aes_key, int size);
    int EnclaveAesEncryption(const uint8_t *input_buffer, uint32_t size,
                             uint8_t *output_buffer, uint8_t *mac_buffer);

    int EnclaveAesDecryption(const uint8_t *input_buffer, uint32_t size,
                             uint8_t *output_buffer, const uint8_t *mac_buffer);



	static sgx_ec256_private_t g_sp_priv_key = {
	    {
	        0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	        0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	        0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	        0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
	    }
	};

int enclave_ra_build_msg2(sgx_ec256_public_t *g_a, sgx_ra_msg2_t *msg2_raw, uint32_t msg2_len, const uint8_t *sig_rl, uint32_t sig_rl_size);

#if defined(__cplusplus)
}
#endif

#endif // GUARD_ENCLAVE_H
