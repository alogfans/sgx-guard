#include <sgx_tcrypto.h>
#include <iostream>
#include <string>
#include <unistd.h>

#include "Enclave.h"
#include "Enclave_t.h"

int EnclaveAesEncryption(const uint8_t *input_buffer, uint32_t size, uint8_t *output_buffer, uint8_t *mac_buffer) {
    sgx_status_t status;
    auto mac = (sgx_aes_gcm_128bit_tag_t *) mac_buffer;
    uint8_t iv[12] = { 0 };

    status = sgx_rijndael128GCM_encrypt(&aes_key, input_buffer, size, output_buffer, iv, 12, NULL, 0, mac);
    return status;
}

int EnclaveAesDecryption(const uint8_t *input_buffer, uint32_t size, uint8_t *output_buffer, const uint8_t *mac_buffer) {
    sgx_status_t status;
    auto mac = (const sgx_aes_gcm_128bit_tag_t *) mac_buffer;
    uint8_t iv[12] = { 0 };

    status = sgx_rijndael128GCM_decrypt(&aes_key, input_buffer, size, output_buffer, iv, 12, NULL, 0, mac);
    return status;
}
