//
// Created by alogfans on 5/24/18.
//

#ifndef GUARD_ENCLAVE_LOADER_H
#define GUARD_ENCLAVE_LOADER_H


#include <string>
#include <sgx_eid.h>

class EnclaveLoader {
public:
    EnclaveLoader(const std::string &enclave_path, const std::string &token_path, int debug_flag = 0);
    virtual ~EnclaveLoader();

public:
    sgx_enclave_id_t enclave_id;
};


#endif // GUARD_ENCLAVE_LOADER_H
