#ifndef GUARD_ENCLAVE_H
#define GUARD_ENCLAVE_H

#include <stdlib.h>
#include <assert.h>
#include <sgx_key_exchange.h>

#if defined(__cplusplus)
extern "C" {
#endif
    // local public key and private key, for secure exchange
    static sgx_ec256_public_t  public_key;
    static sgx_ec256_private_t private_key;
    static uint8_t sealed_aes_key[2048] = { 0 };

    sgx_status_t enclave_aes_key(const uint8_t *aes_key_enc, int size);

    sgx_status_t enclave_aes_encrypt(const uint8_t *input_buffer,
                                     uint32_t size,
                                     uint8_t *output_buffer,
                                     uint8_t *mac_buffer);

    sgx_status_t enclave_aes_decrypt(const uint8_t *input_buffer,
                                     uint32_t size,
                                     uint8_t *output_buffer,
                                     const uint8_t *mac_buffer);

	sgx_status_t enclave_ra_build_msg2(sgx_ec256_public_t *g_a,
									   sgx_ra_msg2_t *msg2_raw,
									   uint32_t msg2_len,
									   const uint8_t *sig_rl,
									   uint32_t sig_rl_size,
                                       uint8_t *spid);

#if defined(__cplusplus)
}
#endif

#endif // GUARD_ENCLAVE_H
