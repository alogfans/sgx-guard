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

static sgx_status_t SGX_CDECL sgx_enclave_aes_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_aes_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_aes_key_t* ms = SGX_CAST(ms_enclave_aes_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_enc_aes_key = ms->ms_enc_aes_key;
	int _tmp_size = ms->ms_size;
	size_t _len_enc_aes_key = _tmp_size * sizeof(*_tmp_enc_aes_key);
	uint8_t* _in_enc_aes_key = NULL;

	if (sizeof(*_tmp_enc_aes_key) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_enc_aes_key))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_enc_aes_key, _len_enc_aes_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_enc_aes_key != NULL && _len_enc_aes_key != 0) {
		_in_enc_aes_key = (uint8_t*)malloc(_len_enc_aes_key);
		if (_in_enc_aes_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_enc_aes_key, _tmp_enc_aes_key, _len_enc_aes_key);
	}

	ms->ms_retval = enclave_aes_key((const uint8_t*)_in_enc_aes_key, _tmp_size);
err:
	if (_in_enc_aes_key) free((void*)_in_enc_aes_key);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_aes_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_aes_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_aes_encrypt_t* ms = SGX_CAST(ms_enclave_aes_encrypt_t*, pms);
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

	ms->ms_retval = enclave_aes_encrypt((const uint8_t*)_in_input_buffer, _tmp_size, _in_output_buffer, _in_mac_buffer);
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

static sgx_status_t SGX_CDECL sgx_enclave_aes_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_aes_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_aes_decrypt_t* ms = SGX_CAST(ms_enclave_aes_decrypt_t*, pms);
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

	ms->ms_retval = enclave_aes_decrypt((const uint8_t*)_in_input_buffer, _tmp_size, _in_output_buffer, (const uint8_t*)_in_mac_buffer);
err:
	if (_in_input_buffer) free((void*)_in_input_buffer);
	if (_in_output_buffer) {
		memcpy(_tmp_output_buffer, _in_output_buffer, _len_output_buffer);
		free(_in_output_buffer);
	}
	if (_in_mac_buffer) free((void*)_in_mac_buffer);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_build_msg2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_build_msg2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_build_msg2_t* ms = SGX_CAST(ms_enclave_ra_build_msg2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(*_tmp_g_a);
	sgx_ec256_public_t* _in_g_a = NULL;
	sgx_ra_msg2_t* _tmp_msg2_raw = ms->ms_msg2_raw;
	size_t _len_msg2_raw = sizeof(*_tmp_msg2_raw);
	sgx_ra_msg2_t* _in_msg2_raw = NULL;
	uint8_t* _tmp_sig_rl = ms->ms_sig_rl;
	uint32_t _tmp_sig_rl_size = ms->ms_sig_rl_size;
	size_t _len_sig_rl = _tmp_sig_rl_size * sizeof(*_tmp_sig_rl);
	uint8_t* _in_sig_rl = NULL;
	uint8_t* _tmp_spid = ms->ms_spid;
	size_t _len_spid = 16 * sizeof(*_tmp_spid);
	uint8_t* _in_spid = NULL;

	if (sizeof(*_tmp_sig_rl) != 0 &&
		(size_t)_tmp_sig_rl_size > (SIZE_MAX / sizeof(*_tmp_sig_rl))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_spid) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_spid))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);
	CHECK_UNIQUE_POINTER(_tmp_msg2_raw, _len_msg2_raw);
	CHECK_UNIQUE_POINTER(_tmp_sig_rl, _len_sig_rl);
	CHECK_UNIQUE_POINTER(_tmp_spid, _len_spid);

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
	if (_tmp_msg2_raw != NULL && _len_msg2_raw != 0) {
		if ((_in_msg2_raw = (sgx_ra_msg2_t*)malloc(_len_msg2_raw)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_msg2_raw, 0, _len_msg2_raw);
	}
	if (_tmp_sig_rl != NULL && _len_sig_rl != 0) {
		_in_sig_rl = (uint8_t*)malloc(_len_sig_rl);
		if (_in_sig_rl == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_sig_rl, _tmp_sig_rl, _len_sig_rl);
	}
	if (_tmp_spid != NULL && _len_spid != 0) {
		_in_spid = (uint8_t*)malloc(_len_spid);
		if (_in_spid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_spid, _tmp_spid, _len_spid);
	}

	ms->ms_retval = enclave_ra_build_msg2(_in_g_a, _in_msg2_raw, ms->ms_msg2_len, (const uint8_t*)_in_sig_rl, _tmp_sig_rl_size, _in_spid);
err:
	if (_in_g_a) free(_in_g_a);
	if (_in_msg2_raw) {
		memcpy(_tmp_msg2_raw, _in_msg2_raw, _len_msg2_raw);
		free(_in_msg2_raw);
	}
	if (_in_sig_rl) free((void*)_in_sig_rl);
	if (_in_spid) free(_in_spid);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_enclave_aes_key, 0},
		{(void*)(uintptr_t)sgx_enclave_aes_encrypt, 0},
		{(void*)(uintptr_t)sgx_enclave_aes_decrypt, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_build_msg2, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


