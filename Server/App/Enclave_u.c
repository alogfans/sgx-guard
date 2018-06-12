#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_SetAesKey_t {
	int ms_retval;
	uint8_t* ms_aes_key;
	int ms_size;
} ms_SetAesKey_t;

typedef struct ms_GetAesKey_t {
	int ms_retval;
	uint8_t* ms_aes_key;
	int ms_size;
} ms_GetAesKey_t;

typedef struct ms_EnclaveAesEncryption_t {
	int ms_retval;
	uint8_t* ms_input_buffer;
	uint32_t ms_size;
	uint8_t* ms_output_buffer;
	uint8_t* ms_mac_buffer;
} ms_EnclaveAesEncryption_t;

typedef struct ms_EnclaveAesDecryption_t {
	int ms_retval;
	uint8_t* ms_input_buffer;
	uint32_t ms_size;
	uint8_t* ms_output_buffer;
	uint8_t* ms_mac_buffer;
} ms_EnclaveAesDecryption_t;

typedef struct ms_enclave_build_msg1_t {
	int ms_retval;
	sgx_ec256_public_t* ms_g_a;
	sgx_ec256_public_t* ms_g_b;
	sgx_ec256_signature_t* ms_sign_gb_ga;
	sgx_cmac_128bit_tag_t* ms_mac;
} ms_enclave_build_msg1_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t SetAesKey(sgx_enclave_id_t eid, int* retval, const uint8_t* aes_key, int size)
{
	sgx_status_t status;
	ms_SetAesKey_t ms;
	ms.ms_aes_key = (uint8_t*)aes_key;
	ms.ms_size = size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t GetAesKey(sgx_enclave_id_t eid, int* retval, uint8_t* aes_key, int size)
{
	sgx_status_t status;
	ms_GetAesKey_t ms;
	ms.ms_aes_key = aes_key;
	ms.ms_size = size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t EnclaveAesEncryption(sgx_enclave_id_t eid, int* retval, const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, uint8_t* mac_buffer)
{
	sgx_status_t status;
	ms_EnclaveAesEncryption_t ms;
	ms.ms_input_buffer = (uint8_t*)input_buffer;
	ms.ms_size = size;
	ms.ms_output_buffer = output_buffer;
	ms.ms_mac_buffer = mac_buffer;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t EnclaveAesDecryption(sgx_enclave_id_t eid, int* retval, const uint8_t* input_buffer, uint32_t size, uint8_t* output_buffer, const uint8_t* mac_buffer)
{
	sgx_status_t status;
	ms_EnclaveAesDecryption_t ms;
	ms.ms_input_buffer = (uint8_t*)input_buffer;
	ms.ms_size = size;
	ms.ms_output_buffer = output_buffer;
	ms.ms_mac_buffer = (uint8_t*)mac_buffer;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_build_msg1(sgx_enclave_id_t eid, int* retval, sgx_ec256_public_t* g_a, sgx_ec256_public_t* g_b, sgx_ec256_signature_t* sign_gb_ga, sgx_cmac_128bit_tag_t* mac)
{
	sgx_status_t status;
	ms_enclave_build_msg1_t ms;
	ms.ms_g_a = g_a;
	ms.ms_g_b = g_b;
	ms.ms_sign_gb_ga = sign_gb_ga;
	ms.ms_mac = mac;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

