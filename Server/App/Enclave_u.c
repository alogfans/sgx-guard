#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_enclave_aes_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_enc_aes_key;
	int ms_size;
} ms_enclave_aes_key_t;

typedef struct ms_enclave_aes_encrypt_t {
	sgx_status_t ms_retval;
	uint8_t* ms_input_buffer;
	uint32_t ms_size;
	uint8_t* ms_output_buffer;
	uint8_t* ms_mac_buffer;
} ms_enclave_aes_encrypt_t;

typedef struct ms_enclave_aes_decrypt_t {
	sgx_status_t ms_retval;
	uint8_t* ms_input_buffer;
	uint32_t ms_size;
	uint8_t* ms_output_buffer;
	uint8_t* ms_mac_buffer;
} ms_enclave_aes_decrypt_t;

typedef struct ms_enclave_ra_build_msg2_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_g_a;
	sgx_ra_msg2_t* ms_msg2_raw;
	uint32_t ms_msg2_len;
	uint8_t* ms_sig_rl;
	uint32_t ms_sig_rl_size;
	uint8_t* ms_spid;
} ms_enclave_ra_build_msg2_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t enclave_aes_key(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* enc_aes_key, int size)
{
	sgx_status_t status;
	ms_enclave_aes_key_t ms;
	ms.ms_enc_aes_key = (uint8_t*)enc_aes_key;
	ms.ms_size = size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_aes_encrypt(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, uint8_t* mac_buffer)
{
	sgx_status_t status;
	ms_enclave_aes_encrypt_t ms;
	ms.ms_input_buffer = (uint8_t*)input_buffer;
	ms.ms_size = size;
	ms.ms_output_buffer = output_buffer;
	ms.ms_mac_buffer = mac_buffer;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_aes_decrypt(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, const uint8_t* mac_buffer)
{
	sgx_status_t status;
	ms_enclave_aes_decrypt_t ms;
	ms.ms_input_buffer = (uint8_t*)input_buffer;
	ms.ms_size = size;
	ms.ms_output_buffer = output_buffer;
	ms.ms_mac_buffer = (uint8_t*)mac_buffer;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_build_msg2(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* g_a, sgx_ra_msg2_t* msg2_raw, uint32_t msg2_len, const uint8_t* sig_rl, uint32_t sig_rl_size, uint8_t* spid)
{
	sgx_status_t status;
	ms_enclave_ra_build_msg2_t ms;
	ms.ms_g_a = g_a;
	ms.ms_msg2_raw = msg2_raw;
	ms.ms_msg2_len = msg2_len;
	ms.ms_sig_rl = (uint8_t*)sig_rl;
	ms.ms_sig_rl_size = sig_rl_size;
	ms.ms_spid = spid;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

