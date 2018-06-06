//
// Created by alogfans on 5/24/18.
//

#include "EnclaveLoader.h"
#include "sgx_urts.h"

#include <unistd.h>
#include <iostream>
#include <cstring>

EnclaveLoader::EnclaveLoader(const std::string &enclave_path, const std::string &token_path, int debug_flag) {
    FILE *token_fd = fopen(token_path.c_str(), "rb");
    if (!token_fd) {
        token_fd = fopen(token_path.c_str(), "wb");
    }

    if (!token_fd) {
        perror("open/create token file failed");
        exit(EXIT_FAILURE);
    }

    sgx_launch_token_t token = { 0 };
    size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), token_fd);
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
        // if token is invalid, clear the buffer
        memset(&token, 0x0, sizeof(sgx_launch_token_t));
    }

    int token_updated = 0;
    sgx_status_t ret;
    ret = sgx_create_enclave(enclave_path.c_str(), debug_flag, &token, &token_updated, &enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
        std::cerr << "sgx_create_enclave failed: " << ret << std::endl;
        fclose(token_fd);
        exit(EXIT_FAILURE);
    }

    if (token_updated) {
        token_fd = freopen(token_path.c_str(), "wb", token_fd);
        if (!token_fd) {
            perror("open/create token file failed");
            exit(EXIT_FAILURE);
        }

        size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), token_fd);
        if (write_num == -1) {
            perror("failed to Write token file properly");
            fclose(token_fd);
            exit(EXIT_FAILURE);
        }

        if (write_num != sizeof(sgx_launch_token_t)) {
            std::cerr << "failed to Write token file properly: end of file" << std::endl;
            fclose(token_fd);
            exit(EXIT_FAILURE);
        }
    }

    fclose(token_fd);
}

EnclaveLoader::~EnclaveLoader() {
    if (enclave_id != 0) {
        sgx_destroy_enclave(enclave_id);
        enclave_id = 0;
    }
}
