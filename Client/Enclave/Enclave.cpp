#include <sgx_tcrypto.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tseal.h>
#include <cstring>
#include "Enclave.h"
#include "Enclave_t.h"

#define CHECK(x) { sgx_status_t ret; if (ret = (x)) { return ret; } }

sgx_status_t enclave_ra_create(int b_pse, uint32_t *context) {
    sgx_status_t status;
    sgx_ecc_state_handle_t ecc_state;
    memset(&local_pubkey, 0, sizeof(sgx_ec256_public_t));
    memset(&local_prikey, 0, sizeof(sgx_ec256_private_t));

    CHECK(sgx_ecc256_open_context(&ecc_state));
    CHECK(sgx_ecc256_create_key_pair(&local_prikey, &local_pubkey, ecc_state));
    CHECK(sgx_ecc256_close_context(ecc_state));

    if (b_pse) {
        status = sgx_create_pse_session();
        if (status != SGX_SUCCESS) {
            return status;
        }
    }

static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};


    status = sgx_ra_init(&g_sp_pub_key, b_pse, context);

    if (b_pse) {
        sgx_close_pse_session();
    }

    return status;
}

sgx_status_t enclave_ra_close(uint32_t context) {
    return sgx_ra_close(context);
}

sgx_status_t enclave_ra_set_remote_pubkey(const sgx_ec256_public_t pubkey) {
    memcpy(&remote_pubkey, &pubkey, sizeof(sgx_ec256_public_t));
    return SGX_SUCCESS;
}


int enclave_seal_size(uint32_t payload_size) {
    return sgx_calc_sealed_data_size(0, payload_size);
}

sgx_status_t enclave_seal_aes_key(uint8_t *aes_key, uint32_t sealed_size, uint8_t *sealed) {
    return sgx_seal_data(0, NULL, 16, aes_key, sealed_size, (sgx_sealed_data_t *) sealed);
}

