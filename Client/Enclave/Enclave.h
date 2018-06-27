#ifndef GUARD_ENCLAVE_H
#define GUARD_ENCLAVE_H

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

    static sgx_ec256_public_t local_pubkey, remote_pubkey;
    static sgx_ec256_private_t local_prikey;

    sgx_status_t enclave_ra_create(int b_pse, uint32_t *context);
    sgx_status_t enclave_ra_close(uint32_t context);
    sgx_status_t enclave_ra_set_remote_pubkey(const sgx_ec256_public_t pubkey);

    sgx_status_t enclave_seal_aes_key(uint8_t *aes_key, uint32_t sealed_size, uint8_t *sealed);

    int enclave_seal_size(uint32_t payload_size);

#if defined(__cplusplus)
}
#endif

#endif // GUARD_ENCLAVE_H
