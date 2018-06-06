#ifndef GUARD_ENCLAVE_H
#define GUARD_ENCLAVE_H

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

    static const sgx_aes_gcm_128bit_key_t aes_key = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                                                      0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

    int EnclaveAesEncryption(const uint8_t *input_buffer, uint32_t size,
                             uint8_t *output_buffer, uint8_t *mac_buffer);

    int EnclaveAesDecryption(const uint8_t *input_buffer, uint32_t size,
                             uint8_t *output_buffer, const uint8_t *mac_buffer);

#if defined(__cplusplus)
}
#endif

#endif // GUARD_ENCLAVE_H
