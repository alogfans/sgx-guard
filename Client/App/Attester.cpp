//
// Created by alogfans on 6/5/18.
//

#include "Attester.h"
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <iostream>

#define ATT_MSG0    100
#define ATT_MSG1    101
#define ATT_MSG2    102
#define ATT_MSG3    103
#define ATT_ERR     104

Attester::Attester(const EnclaveLoader &loader) : loader(loader) {
    sgx_status_t ret, ret_call;

    ret = sgx_get_extended_epid_group_id(&epid_group_id);
    if (ret != SGX_SUCCESS) {
        std::cerr << "sgx_create_enclave failed: " << ret << std::endl;
        exit(EXIT_FAILURE);
    }

    ret = encalve_init_ra(loader.enclave_id, (int *) &ret_call, 1, &ra_context);
    if (ret != SGX_SUCCESS || ret_call != SGX_SUCCESS) {
        std::cerr << "encalve_init_ra failed: " << ret << ", " << ret_call << std::endl;
        exit(EXIT_FAILURE);
    }
}

Attester::~Attester() {
    sgx_status_t ret, ret_call;
    ret = encalve_close_ra(loader.enclave_id, (int *) &ret_call, ra_context);
    if (ret != SGX_SUCCESS || ret_call != SGX_SUCCESS) {
        std::cerr << "encalve_close_ra failed: " << ret << ", " << ret_call << std::endl;
    }
}


void Attester::buildMsg0(std::vector<uint8_t> &msg) {
    msg.resize(sizeof(uint32_t));
    memcpy(msg.data(), &epid_group_id, sizeof(uint32_t));
}

void Attester::buildMsg1(std::vector <uint8_t> &msg){
    sgx_ra_msg1_t msg_payload;
    sgx_status_t ret = sgx_ra_get_msg1(ra_context, loader.enclave_id, sgx_ra_get_ga, &msg_payload);
    if (ret != SGX_SUCCESS) {
        std::cerr << "sgx_ra_get_msg1 failed: " << ret << std::endl;
        exit(EXIT_FAILURE);
    }

    msg.resize(sizeof(msg_payload));
    memcpy(msg.data(), &msg_payload, sizeof(msg_payload));
}

void Attester::buildMsg3(const std::vector<uint8_t> &recv_msg2, std::vector<uint8_t> &msg3){
    sgx_ra_msg3_t *msg3_payload;
    uint32_t msg3_size;
    sgx_status_t ret = sgx_ra_proc_msg2(ra_context, loader.enclave_id, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
            (const sgx_ra_msg2_t *) recv_msg2.data(), (uint32_t) recv_msg2.size(),
            &msg3_payload, &msg3_size);

    if (ret != SGX_SUCCESS) {
        std::cerr << "sgx_ra_proc_msg2 failed: " << ret << std::endl;
        exit(EXIT_FAILURE);
    }

    msg3.resize(msg3_size);
    memcpy(msg3.data(), msg3_payload, msg3_size);
    free(msg3_payload);
}

void Attester::Attest(Socket &socket) {
    int cmd_type_ret;

    std::vector<uint8_t> msg0, msg1, msg2, msg3;
    buildMsg0(msg0);
    socket.WriteCommand(ATT_MSG0, msg0);
    socket.ReadCommand(cmd_type_ret, msg0);
    if (cmd_type_ret == ATT_ERR) {
        const char *str_buf = (const char *) msg0.data();
        printf("error %s\n", str_buf);
        exit(EXIT_FAILURE);
    }

    buildMsg1(msg1);
    socket.WriteCommand(ATT_MSG1, msg1);
    socket.ReadCommand(cmd_type_ret, msg2);
    if (cmd_type_ret == ATT_ERR) {
        const char *str_buf = (const char *) msg2.data();
        printf("error %s\n", str_buf);
        exit(EXIT_FAILURE);
    } else if (cmd_type_ret != ATT_MSG2) {
        printf("wrong command received\n");
        exit(EXIT_FAILURE);
    }

    buildMsg3(msg2, msg3);
    socket.WriteCommand(ATT_MSG3, msg3);
    socket.ReadCommand(cmd_type_ret, msg3);
    if (cmd_type_ret == ATT_ERR) {
        const char *str_buf = (const char *) msg2.data();
        printf("error %s\n", str_buf);
        exit(EXIT_FAILURE);
    }
}
