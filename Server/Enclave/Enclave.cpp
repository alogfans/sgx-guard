#include <iostream>
#include <string>
#include <unistd.h>
#include <sgx_tseal.h>

#include "Enclave.h"
#include "Enclave_t.h"

int SetAesKey(const uint8_t *p_aes_key, int size) {
    uint32_t mac_size = 0, data_size = 16;
    return sgx_unseal_data((const sgx_sealed_data_t*) p_aes_key, NULL, &mac_size, aes_key, &data_size);
}

int GetAesKey(uint8_t *p_aes_key, int size) {
    memcpy(p_aes_key, aes_key, size);
    return 0;
}

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

bool derive_key(const sgx_ec256_dh_shared_t *p_shared_key,
                uint8_t key_id,
                sgx_ec_key_128bit_t *first_derived_key,
                sgx_ec_key_128bit_t *second_derived_key) {

    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    hash_buffer.counter[3] = key_id;

    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t) ; i++)
    {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s) - 1 - i];
    }

    sgx_sha256_init(&sha_context);
    sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    sgx_sha256_update((uint8_t*)ID_U, sizeof(ID_U), sha_context);
    sgx_sha256_update((uint8_t*)ID_V, sizeof(ID_V), sha_context);
    sgx_sha256_get_hash(sha_context, &key_material);
    sgx_sha256_close(sha_context);

    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    return true;
}

int enclave_build_msg1(sgx_ec256_public_t *g_a, sgx_ec256_public_t *g_b, sgx_ec256_signature_t *sign_gb_ga, sgx_cmac_128bit_tag_t *mac) {
    sgx_ecc_state_handle_t ecc_state;

    sgx_ec256_public_t public_key;
    sgx_ec256_private_t private_key;
    sgx_ec256_dh_shared_t dh_key;

    memset(&public_key, 0, sizeof(sgx_ec256_public_t));
    memset(&private_key, 0, sizeof(sgx_ec256_private_t));
    memset(&dh_key, 0, sizeof(sgx_ec256_dh_shared_t));

    sgx_ecc256_open_context(&ecc_state);
    sgx_ecc256_create_key_pair(&private_key, &public_key, ecc_state);
    sgx_ecc256_compute_shared_dhkey(&private_key, g_a, &dh_key, ecc_state);

    sgx_ec_key_128bit_t smk_key, sk_key, mk_key, vk_key;

    derive_key(&dh_key, 0, &smk_key, &sk_key);
    derive_key(&dh_key, 1, &mk_key, &vk_key);

    sgx_ec256_public_t gb_ga[2];
    memcpy(g_b, &public_key, sizeof(sgx_ec256_public_t));
    memcpy(&gb_ga[0], &public_key, sizeof(sgx_ec256_public_t));
    memcpy(&gb_ga[1], g_a, sizeof(sgx_ec256_public_t));

    sgx_ecdsa_sign((uint8_t *) &gb_ga, sizeof(gb_ga), &g_sp_priv_key, sign_gb_ga, ecc_state);
    sgx_rijndael128_cmac_msg(&smk_key, (uint8_t *) &public_key, sizeof(public_key), mac);

    sgx_ecc256_close_context(ecc_state);
}