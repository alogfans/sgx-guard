//
// Created by alogfans on 6/5/18.
//

#include "RAClient.h"
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <iostream>

#define ATT_MSG0     100
#define ATT_MSG0_ACK 105
#define ATT_MSG1     101
#define ATT_MSG2     102
#define ATT_MSG3     103
#define ATT_MSG4     106
#define ATT_ERR      104

RAClient::RAClient(const EnclaveLoader &loader) : loader(loader) {
    sgx_status_t ret, ret_call;

    ret = sgx_get_extended_epid_group_id(&epid_group_id);
    if (ret != SGX_SUCCESS) {
        std::cerr << "sgx_create_enclave failed: " << ret << std::endl;
        exit(EXIT_FAILURE);
    }

    ret = enclave_ra_create(loader.enclave_id, &ret_call, 1, &ra_context);
    if (ret != SGX_SUCCESS || ret_call != SGX_SUCCESS) {
        std::cerr << "encalve_init_ra failed: " << ret << ", " << ret_call << std::endl;
        exit(EXIT_FAILURE);
    }
}

RAClient::~RAClient() {
    sgx_status_t ret, ret_call;
    ret = enclave_ra_close(loader.enclave_id, &ret_call, ra_context);
    if (ret != SGX_SUCCESS || ret_call != SGX_SUCCESS) {
        std::cerr << "encalve_close_ra failed: " << ret << ", " << ret_call << std::endl;
    }
}

void RAClient::buildMsg0(std::vector<uint8_t> &msg0) {
    msg0.resize(sizeof(uint32_t));
    memcpy(msg0.data(), &epid_group_id, sizeof(uint32_t));
}

void RAClient::buildMsg1(std::vector <uint8_t> &msg1){
    sgx_ra_msg1_t msg_payload;
    sgx_status_t ret = sgx_ra_get_msg1(ra_context, loader.enclave_id, sgx_ra_get_ga, &msg_payload);
    if (ret != SGX_SUCCESS) {
        std::cerr << "sgx_ra_get_msg1 failed: " << ret << std::endl;
        exit(EXIT_FAILURE);
    }

    msg1.resize(sizeof(msg_payload));
    memcpy(msg1.data(), &msg_payload, sizeof(msg_payload));
}

void RAClient::buildMsg3(const std::vector<uint8_t> &msg2, std::vector<uint8_t> &msg3){
    const sgx_ra_msg2_t *msg2_payload = (const sgx_ra_msg2_t *) msg2.data();
    sgx_ra_msg3_t *msg3_payload;
    uint32_t msg3_size;
    sgx_status_t ret, ret_call;

    ret = enclave_ra_set_remote_pubkey(loader.enclave_id, &ret_call, msg2_payload->g_b);
    if (ret != SGX_SUCCESS || ret_call != SGX_SUCCESS) {
        std::cerr << "enclave_ra_set_remote_pubkey failed: " << ret << ", " << ret_call << std::endl;
        exit(EXIT_FAILURE);
    }

    ret = sgx_ra_proc_msg2(ra_context, loader.enclave_id, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
                           msg2_payload, (uint32_t) msg2.size(), &msg3_payload, &msg3_size);

    if (ret != SGX_SUCCESS) {
        std::cerr << "sgx_ra_proc_msg2 failed: " << ret << std::endl;
        exit(EXIT_FAILURE);
    }

    msg3.resize(msg3_size);
    memcpy(msg3.data(), msg3_payload, msg3_size);
    free(msg3_payload);
}

void assert_msg(int cmd_type_ret, int cmd_type_should, const std::vector<uint8_t> &msg) {
    if (cmd_type_ret == ATT_ERR) {
        const char *str_buf = (const char *) msg.data();
        printf("error %s\n", str_buf);
        exit(EXIT_FAILURE);
    }

    if (cmd_type_ret != cmd_type_should) {
        printf("message type error\n");
        exit(EXIT_FAILURE);
    }
}

void RAClient::Attest(Socket &socket) {
    int cmd_type_ret;
    std::vector<uint8_t> msg0, msg1, msg2, msg3, msg4;
    printf("checkpoint: start attestation\n");
    // msg0 -- msg0_cbk
    buildMsg0(msg0);
    socket.WriteCommand(ATT_MSG0, msg0);
    socket.ReadCommand(cmd_type_ret, msg0);
    printf("%d\n", cmd_type_ret);
    assert_msg(cmd_type_ret, ATT_MSG0_ACK, msg0);

    // msg1 -- msg2
    buildMsg1(msg1);
    socket.WriteCommand(ATT_MSG1, msg1);
    socket.ReadCommand(cmd_type_ret, msg2);
    assert_msg(cmd_type_ret, ATT_MSG2, msg2);

    // msg3 -- msg4
    buildMsg3(msg2, msg3);
    socket.WriteCommand(ATT_MSG3, msg3);
    socket.ReadCommand(cmd_type_ret, msg3);
    assert_msg(cmd_type_ret, ATT_MSG4, msg4);

    // Completed
}
