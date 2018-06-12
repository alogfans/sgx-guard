#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_SetAesKey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_SetAesKey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_SetAesKey_t* ms = SGX_CAST(ms_SetAesKey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	int _tmp_size = ms->ms_size;
	size_t _len_aes_key = _tmp_size * sizeof(*_tmp_aes_key);
	uint8_t* _in_aes_key = NULL;

	if (sizeof(*_tmp_aes_key) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_aes_key))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		_in_aes_key = (uint8_t*)malloc(_len_aes_key);
		if (_in_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_aes_key, _tmp_aes_key, _len_aes_key);
	}

	ms->ms_retval = SetAesKey((const uint8_t*)_in_aes_key, _tmp_size);
err:
	if (_in_aes_key) free((void*)_in_aes_key);

	return status;
}

static sgx_status_t SGX_CDECL sgx_GetAesKey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_GetAesKey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_GetAesKey_t* ms = SGX_CAST(ms_GetAesKey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_aes_key = ms->ms_aes_key;
	int _tmp_size = ms->ms_size;
	size_t _len_aes_key = _tmp_size * sizeof(*_tmp_aes_key);
	uint8_t* _in_aes_key = NULL;

	if (sizeof(*_tmp_aes_key) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_aes_key))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_aes_key, _len_aes_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_aes_key != NULL && _len_aes_key != 0) {
		if ((_in_aes_key = (uint8_t*)malloc(_len_aes_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_aes_key, 0, _len_aes_key);
	}

	ms->ms_retval = GetAesKey(_in_aes_key, _tmp_size);
err:
	if (_in_aes_key) {
		memcpy(_tmp_aes_key, _in_aes_key, _len_aes_key);
		free(_in_aes_key);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_EnclaveAesEncryption(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_EnclaveAesEncryption_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_EnclaveAesEncryption_t* ms = SGX_CAST(ms_EnclaveAesEncryption_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_input_buffer = ms->ms_input_buffer;
	uint32_t _tmp_size = ms->ms_size;
	size_t _len_input_buffer = _tmp_size * sizeof(*_tmp_input_buffer);
	uint8_t* _in_input_buffer = NULL;
	uint8_t* _tmp_output_buffer = ms->ms_output_buffer;
	size_t _len_output_buffer = _tmp_size * sizeof(*_tmp_output_buffer);
	uint8_t* _in_output_buffer = NULL;
	uint8_t* _tmp_mac_buffer = ms->ms_mac_buffer;
	size_t _len_mac_buffer = 16 * sizeof(*_tmp_mac_buffer);
	uint8_t* _in_mac_buffer = NULL;

	if (sizeof(*_tmp_input_buffer) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_input_buffer))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_output_buffer) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_output_buffer))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_mac_buffer) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_mac_buffer))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_input_buffer, _len_input_buffer);
	CHECK_UNIQUE_POINTER(_tmp_output_buffer, _len_output_buffer);
	CHECK_UNIQUE_POINTER(_tmp_mac_buffer, _len_mac_buffer);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input_buffer != NULL && _len_input_buffer != 0) {
		_in_input_buffer = (uint8_t*)malloc(_len_input_buffer);
		if (_in_input_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_input_buffer, _tmp_input_buffer, _len_input_buffer);
	}
	if (_tmp_output_buffer != NULL && _len_output_buffer != 0) {
		if ((_in_output_buffer = (uint8_t*)malloc(_len_output_buffer)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output_buffer, 0, _len_output_buffer);
	}
	if (_tmp_mac_buffer != NULL && _len_mac_buffer != 0) {
		if ((_in_mac_buffer = (uint8_t*)malloc(_len_mac_buffer)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mac_buffer, 0, _len_mac_buffer);
	}

	ms->ms_retval = EnclaveAesEncryption((const uint8_t*)_in_input_buffer, _tmp_size, _in_output_buffer, _in_mac_buffer);
err:
	if (_in_input_buffer) free((void*)_in_input_buffer);
	if (_in_output_buffer) {
		memcpy(_tmp_output_buffer, _in_output_buffer, _len_output_buffer);
		free(_in_output_buffer);
	}
	if (_in_mac_buffer) {
		memcpy(_tmp_mac_buffer, _in_mac_buffer, _len_mac_buffer);
		free(_in_mac_buffer);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_EnclaveAesDecryption(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_EnclaveAesDecryption_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_EnclaveAesDecryption_t* ms = SGX_CAST(ms_EnclaveAesDecryption_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_input_buffer = ms->ms_input_buffer;
	uint32_t _tmp_size = ms->ms_size;
	size_t _len_input_buffer = _tmp_size * sizeof(*_tmp_input_buffer);
	uint8_t* _in_input_buffer = NULL;
	uint8_t* _tmp_output_buffer = ms->ms_output_buffer;
	size_t _len_output_buffer = _tmp_size * sizeof(*_tmp_output_buffer);
	uint8_t* _in_output_buffer = NULL;
	uint8_t* _tmp_mac_buffer = ms->ms_mac_buffer;
	size_t _len_mac_buffer = 16 * sizeof(*_tmp_mac_buffer);
	uint8_t* _in_mac_buffer = NULL;

	if (sizeof(*_tmp_input_buffer) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_input_buffer))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_output_buffer) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_output_buffer))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_mac_buffer) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_mac_buffer))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_input_buffer, _len_input_buffer);
	CHECK_UNIQUE_POINTER(_tmp_output_buffer, _len_output_buffer);
	CHECK_UNIQUE_POINTER(_tmp_mac_buffer, _len_mac_buffer);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input_buffer != NULL && _len_input_buffer != 0) {
		_in_input_buffer = (uint8_t*)malloc(_len_input_buffer);
		if (_in_input_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_input_buffer, _tmp_input_buffer, _len_input_buffer);
	}
	if (_tmp_output_buffer != NULL && _len_output_buffer != 0) {
		if ((_in_output_buffer = (uint8_t*)malloc(_len_output_buffer)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output_buffer, 0, _len_output_buffer);
	}
	if (_tmp_mac_buffer != NULL && _len_mac_buffer != 0) {
		_in_mac_buffer = (uint8_t*)malloc(_len_mac_buffer);
		if (_in_mac_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_mac_buffer, _tmp_mac_buffer, _len_mac_buffer);
	}

	ms->ms_retval = EnclaveAesDecryption((const uint8_t*)_in_input_buffer, _tmp_size, _in_output_buffer, (const uint8_t*)_in_mac_buffer);
err:
	if (_in_input_buffer) free((void*)_in_input_buffer);
	if (_in_output_buffer) {
		memcpy(_tmp_output_buffer, _in_output_buffer, _len_output_buffer);
		free(_in_output_buffer);
	}
	if (_in_mac_buffer) free((void*)_in_mac_buffer);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_build_msg1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_build_msg1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_build_msg1_t* ms = SGX_CAST(ms_enclave_build_msg1_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(*_tmp_g_a);
	sgx_ec256_public_t* _in_g_a = NULL;
	sgx_ec256_public_t* _tmp_g_b = ms->ms_g_b;
	size_t _len_g_b = sizeof(*_tmp_g_b);
	sgx_ec256_public_t* _in_g_b = NULL;
	sgx_ec256_signature_t* _tmp_sign_gb_ga = ms->ms_sign_gb_ga;
	size_t _len_sign_gb_ga = sizeof(*_tmp_sign_gb_ga);
	sgx_ec256_signature_t* _in_sign_gb_ga = NULL;
	sgx_cmac_128bit_tag_t* _tmp_mac = ms->ms_mac;
	size_t _len_mac = sizeof(*_tmp_mac);
	sgx_cmac_128bit_tag_t* _in_mac = NULL;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);
	CHECK_UNIQUE_POINTER(_tmp_g_b, _len_g_b);
	CHECK_UNIQUE_POINTER(_tmp_sign_gb_ga, _len_sign_gb_ga);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a);
		if (_in_g_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_g_a, _tmp_g_a, _len_g_a);
	}
	if (_tmp_g_b != NULL && _len_g_b != 0) {
		if ((_in_g_b = (sgx_ec256_public_t*)malloc(_len_g_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_b, 0, _len_g_b);
	}
	if (_tmp_sign_gb_ga != NULL && _len_sign_gb_ga != 0) {
		if ((_in_sign_gb_ga = (sgx_ec256_signature_t*)malloc(_len_sign_gb_ga)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sign_gb_ga, 0, _len_sign_gb_ga);
	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		if ((_in_mac = (sgx_cmac_128bit_tag_t*)malloc(_len_mac)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mac, 0, _len_mac);
	}

	ms->ms_retval = enclave_build_msg1(_in_g_a, _in_g_b, _in_sign_gb_ga, _in_mac);
err:
	if (_in_g_a) free(_in_g_a);
	if (_in_g_b) {
		memcpy(_tmp_g_b, _in_g_b, _len_g_b);
		free(_in_g_b);
	}
	if (_in_sign_gb_ga) {
		memcpy(_tmp_sign_gb_ga, _in_sign_gb_ga, _len_sign_gb_ga);
		free(_in_sign_gb_ga);
	}
	if (_in_mac) {
		memcpy(_tmp_mac, _in_mac, _len_mac);
		free(_in_mac);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_SetAesKey, 0},
		{(void*)(uintptr_t)sgx_GetAesKey, 0},
		{(void*)(uintptr_t)sgx_EnclaveAesEncryption, 0},
		{(void*)(uintptr_t)sgx_EnclaveAesDecryption, 0},
		{(void*)(uintptr_t)sgx_enclave_build_msg1, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


