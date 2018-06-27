//
// Created by alogfans on 6/27/18.
//

#include <cstring>
#include <Enclave_u.h>
#include "RAServer.h"
#include "sgx_urts.h"
#include "base64.h"

#define ATT_MSG0     100
#define ATT_MSG0_ACK 105
#define ATT_MSG1     101
#define ATT_MSG2     102
#define ATT_MSG3     103
#define ATT_MSG4     106
#define ATT_ERR      104

RAServer::RAServer(const EnclaveLoader &loader, IASClient &client, uint8_t *sgid)
        : loader(loader), client(client) {
    memcpy(this->sgid, sgid, 16);
}

bool RAServer::onMsg0Arrival(const std::vector<uint8_t> &msg0) {
    uint32_t extended_epid_group_id;
    memcpy(&extended_epid_group_id, msg0.data(), sizeof(uint32_t));
    if (extended_epid_group_id) {
        return false;
    }
    return true;
}

bool RAServer::onMsg1Arrival(const std::vector<uint8_t> &msg1, std::vector<uint8_t> &msg2) {
    auto msg1_raw = (sgx_ra_msg1_t *) msg1.data();

    // Query via IAS server
    char gid[10];
    sprintf(gid, "%02X%02X%02X%02X", msg1_raw->gid[3], msg1_raw->gid[2], msg1_raw->gid[1], msg1_raw->gid[0]);
    printf("%s\n", gid);

    std::string sigRL;
    if (!client.retrieveSigRL(gid, sigRL)) {
        return false;
    }

    // Query success, send msg2 to client
    msg2.resize(sizeof(sgx_ra_msg2_t) + sigRL.size());
    memset(msg2.data(), 0, msg2.size());

    auto msg2_raw = (sgx_ra_msg2_t *) msg2.data();

    sgx_status_t ret, ret_call;
    ret = enclave_ra_build_msg2(loader.enclave_id,
                                &ret_call,
                                &msg1_raw->g_a,
                                msg2_raw,
                                msg2.size(),
                                (const uint8_t *) sigRL.c_str(),
                                sigRL.size(),
                                sgid);

    return (ret == SGX_SUCCESS);
}

bool RAServer::onMsg3Arrival(const std::vector<uint8_t> &msg3, std::vector<uint8_t> &msg4) {
    auto msg3_raw = (sgx_ra_msg3_t *) msg3.data();
    char encoded_quote[2048] = { 0 };
    Base64::Encode((char *) msg3_raw->quote, msg3.size() - offsetof(sgx_ra_msg3_t, quote), encoded_quote, 2048);
    std::string quote_str(encoded_quote);

    // Query via IAS server
    auto result = client.report(quote_str);
    if (result.empty()) {
        return false;
    }

    if (result["isvEnclaveQuoteStatus"] != "OK" && result["isvEnclaveQuoteStatus"] != "GROUP_OUT_OF_DATE") {
        printf("IAS report: %s\n", result["isvEnclaveQuoteStatus"].c_str());
        return false;
    }

    printf("--- IAS Attestation Success! ---\n");

    for (auto &v : result) {
        printf("%s : %s\n", v.first.c_str(), v.second.c_str());
    }

    return true;
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

void RAServer::write_string(const std::string &str, std::vector<uint8_t> &buf) {
    buf.clear();
    buf.resize(str.size() + 1);
    memcpy(buf.data(), str.c_str(), buf.size());
}

void RAServer::Attest(Socket &socket, const std::vector<uint8_t> &msg0) {
    int cmd_type_ret;
    std::vector<uint8_t> msg0_cbk, msg1, msg2, msg3, msg4;

    // msg0 -- msg0_cbk
    if (onMsg0Arrival(msg0)) {
        socket.WriteCommand(ATT_MSG0_ACK, msg0);
    } else {
        write_string("wrong message", msg0_cbk);
        socket.WriteCommand(ATT_ERR, msg0_cbk);
        return;
    }

    // msg1 -- msg2
    socket.ReadCommand(cmd_type_ret, msg1);
    assert_msg(cmd_type_ret, ATT_MSG1, msg1);
    if (onMsg1Arrival(msg1, msg2)) {
        socket.WriteCommand(ATT_MSG2, msg2);
    } else {
        write_string("wrong message", msg2);
        socket.WriteCommand(ATT_ERR, msg2);
        return;
    }

    // msg3 -- msg4
    socket.ReadCommand(cmd_type_ret, msg3);
    assert_msg(cmd_type_ret, ATT_MSG3, msg3);
    if (onMsg3Arrival(msg3, msg4)) {
        socket.WriteCommand(ATT_MSG4, msg4);
    } else {
        write_string("wrong message", msg4);
        socket.WriteCommand(ATT_ERR, msg4);
        return;
    }
}
