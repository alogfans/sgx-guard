#ifndef GUARD_ENCLAVE_H
#define GUARD_ENCLAVE_H

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

    int encalve_init_ra(int b_pse, uint32_t *context);
    int encalve_close_ra(uint32_t context);
    int enclave_seal_aes_key(uint8_t *aes_key, uint32_t sealed_size, uint8_t *sealed);
    int enclave_seal_size(uint32_t payload_size);
#if defined(__cplusplus)
}
#endif

#endif // GUARD_ENCLAVE_H
