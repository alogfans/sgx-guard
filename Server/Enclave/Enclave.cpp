#include <iostream>
#include <string>
#include <unistd.h>
#include <sgx_tseal.h>

#include "Enclave.h"
#include "Enclave_t.h"

int SetAesKey(const uint8_t *p_aes_key, int size) {
    memcpy(sealed_aes_key, p_aes_key, size);
    return 0;
  //  uint32_t mac_size = 0, data_size = 16;
  //  return sgx_unseal_data((const sgx_sealed_data_t*) p_aes_key, NULL, &mac_size, aes_key, &data_size);
}

int GetAesKey(uint8_t *p_aes_key, int size) {
    uint32_t mac_size = 0, data_size = 16;
    sgx_aes_gcm_128bit_key_t aes_key = { 0 };
    sgx_unseal_data((const sgx_sealed_data_t*) sealed_aes_key, NULL, &mac_size, aes_key, &data_size);

    memcpy(p_aes_key, aes_key, size);
    return 0;
}

int EnclaveAesEncryption(const uint8_t *input_buffer, uint32_t size, uint8_t *output_buffer, uint8_t *mac_buffer) {
    sgx_status_t status;
    auto mac = (sgx_aes_gcm_128bit_tag_t *) mac_buffer;
    uint8_t iv[12] = { 0 };

    uint32_t mac_size = 0, data_size = 16;
    sgx_aes_gcm_128bit_key_t aes_key = { 0 };
    sgx_unseal_data((const sgx_sealed_data_t*) sealed_aes_key, NULL, &mac_size, aes_key, &data_size);
    status = sgx_rijndael128GCM_encrypt(&aes_key, input_buffer, size, output_buffer, iv, 12, NULL, 0, mac);
    return status;
}

int EnclaveAesDecryption(const uint8_t *input_buffer, uint32_t size, uint8_t *output_buffer, const uint8_t *mac_buffer) {
    sgx_status_t status;
    auto mac = (const sgx_aes_gcm_128bit_tag_t *) mac_buffer;
    uint8_t iv[12] = { 0 };

    uint32_t mac_size = 0, data_size = 16;
    sgx_aes_gcm_128bit_key_t aes_key = { 0 };
    sgx_unseal_data((const sgx_sealed_data_t*) sealed_aes_key, NULL, &mac_size, aes_key, &data_size);

    status = sgx_rijndael128GCM_decrypt(&aes_key, input_buffer, size, output_buffer, iv, 12, NULL, 0, mac);
    return status;
}
bool derive_key(const sgx_ec256_dh_shared_t *p_shared_key, const char *label, sgx_ec_key_128bit_t* derived_key) {
    uint32_t label_length = (uint32_t) strlen(label);
    sgx_cmac_128bit_key_t cmac_key;
    sgx_ec_key_128bit_t key_derive_key;
    memset(&cmac_key, 0, sizeof(sgx_cmac_128bit_key_t));
    sgx_rijndael128_cmac_msg(&cmac_key, (uint8_t *) p_shared_key, sizeof(sgx_ec256_dh_shared_t), &key_derive_key);
    /* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
    uint32_t derivation_buffer_length = label_length + 4;
    uint8_t *p_derivation_buffer = (uint8_t *) malloc(derivation_buffer_length);
    memset(p_derivation_buffer, 0, derivation_buffer_length);
    p_derivation_buffer[0] = 0x01;
    memcpy(&p_derivation_buffer[1], label, label_length);
    uint16_t *key_len = (uint16_t *) (&(p_derivation_buffer[derivation_buffer_length - 2]));
    *key_len = 0x0080;
    sgx_rijndael128_cmac_msg(&key_derive_key, p_derivation_buffer, derivation_buffer_length, derived_key);
    free(p_derivation_buffer);
    return true;
}

int enclave_ra_build_msg2(sgx_ec256_public_t *g_a, sgx_ra_msg2_t *msg2_raw, uint32_t msg2_len, const uint8_t *sig_rl, uint32_t sig_rl_size) {
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

    sgx_ec_key_128bit_t smk_key;
    derive_key(&dh_key, "SMK", &smk_key);

    sgx_ec256_public_t gb_ga[2];
    memcpy(&msg2_raw->g_b, &public_key, sizeof(sgx_ec256_public_t));
    memcpy(&gb_ga[0], &public_key, sizeof(sgx_ec256_public_t));
    memcpy(&gb_ga[1], g_a, sizeof(sgx_ec256_public_t));

    uint8_t spid_str[] = { 0x19, 0x0D, 0x7D, 0xF5, 0x89, 0x64, 0x16, 0x6B, 
                           0xE8, 0xD4, 0x48, 0x89, 0x22, 0x55, 0x90, 0x1D };

    memcpy(&msg2_raw->spid, spid_str, sizeof(spid_str));
    msg2_raw->sig_rl_size = sig_rl_size;
    msg2_raw->quote_type = 0;
    msg2_raw->kdf_id = 1;
    memcpy(msg2_raw->sig_rl, sig_rl, sig_rl_size);
    sgx_ecdsa_sign((uint8_t *) &gb_ga, sizeof(gb_ga), &g_sp_priv_key, &msg2_raw->sign_gb_ga, ecc_state);

    const uint32_t mac_size = offsetof(sgx_ra_msg2_t, mac);
    sgx_rijndael128_cmac_msg(&smk_key, (uint8_t *) msg2_raw, mac_size, &msg2_raw->mac);

    sgx_ecc256_close_context(ecc_state);
}
