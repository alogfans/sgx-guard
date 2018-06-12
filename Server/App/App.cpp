#include <iostream>
#include <getopt.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "sgx_urts.h"

#include "CmdParser.h"
#include "EnclaveLoader.h"

#include "Enclave_u.h"
#include "Socket.h"
#include "IASClient.h"

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>

static sgx_enclave_id_t enclave_id;
uint16_t server_port = 8080;

void parse_arguments(int argc, char **argv) {
    CLI::App app{"SGX Guard Service"};
    app.add_option("-p,--port", server_port, "Tcp port that provide SGX Guard Service");

    try {
        app.parse(argc, argv);
    } catch (CLI::ParseError &e) {
        std::exit(app.exit(e));
    }
}

#define CMD_ENCRYPT 1
#define CMD_DECRYPT 2
#define CMD_SET_KEY 3
#define CMD_ERR     4

#define ATT_MSG0    100
#define ATT_MSG1    101
#define ATT_MSG2    102
#define ATT_MSG3    103
#define ATT_CONFIRM 105
#define ATT_ERR     104

void write_string(const std::string &str, std::vector<uint8_t> &buf) {
    buf.clear();
    buf.resize(str.size() + 1);
    memcpy(buf.data(), str.c_str(), buf.size());
}

bool onMsg0Arrival(const std::vector<uint8_t> &msg0) {
    uint32_t extended_epid_group_id;
    memcpy(&extended_epid_group_id, msg0.data(), sizeof(uint32_t));
    if (extended_epid_group_id) {
        return false;
    }

    return true;
}

bool onMsg1Arrival(const std::vector<uint8_t> &msg1, std::vector<uint8_t> &msg2, IASClient &client) {
    auto msg1_raw = (sgx_ra_msg1_t *) msg1.data();

    char gid[10];
    sprintf(gid, "%02X%02X%02X%02X", msg1_raw->gid[3], msg1_raw->gid[2], msg1_raw->gid[1], msg1_raw->gid[0]);
    printf("%s\n", gid);

    std::string sigRL;
    if (!client.retrieveSigRL(gid, sigRL)) {
        return false;
    }

    msg2.resize(sizeof(sgx_ra_msg2_t) + sigRL.size());
    memset(msg2.data(), 0, msg2.size());

    auto msg2_raw = (sgx_ra_msg2_t *) msg2.data();

    int ret = 0;
    enclave_ra_build_msg2(enclave_id, &ret, &msg1_raw->g_a, msg2_raw, msg2.size(), (const uint8_t *) sigRL.c_str(), sigRL.size());
    return (ret == 0);
}

bool onMsg3Arrival(const std::vector<uint8_t> &msg3, std::vector<uint8_t> &msg4, IASClient &client) {
    auto msg3_raw = (sgx_ra_msg3_t *) msg3.data();
    printf("Quote %s\n", (char *) msg3_raw->quote);
    std::string quote_str((char *) msg3_raw->quote);
    auto result = client.report(quote_str);
    if (result.empty()) {
        return false;
    }
    printf("Success!\n");
    return true;
}

bool handle_event(int expected_type, Socket &socket, IASClient &client) {
    int cmd_type;
    std::vector<uint8_t> input_buf, output_buf;

    socket.ReadCommand(cmd_type, input_buf);
    if (cmd_type != expected_type) {
        write_string("wrong message", output_buf);
        socket.WriteCommand(ATT_ERR, output_buf);
        return false;
    }

    // do operation now
    if (cmd_type == ATT_MSG0) {
        if (onMsg0Arrival(input_buf)) {
            socket.WriteCommand(ATT_MSG0, output_buf);
            return true;
        } else {
            write_string("failed for msg 0", output_buf);
            socket.WriteCommand(ATT_ERR, output_buf);
            return false;
        }
    }

    if (cmd_type == ATT_MSG1) {
        if (onMsg1Arrival(input_buf, output_buf, client)) {
            socket.WriteCommand(ATT_MSG2, output_buf);
            return true;
        } else {
            write_string("failed for msg 1", output_buf);
            socket.WriteCommand(ATT_ERR, output_buf);
            return false;
        }
    }

    if (cmd_type == ATT_MSG3) {
        if (onMsg3Arrival(input_buf, output_buf, client)) {
            socket.WriteCommand(ATT_CONFIRM, output_buf);
            return true;
        } else {
            write_string("failed for msg 1", output_buf);
            socket.WriteCommand(ATT_ERR, output_buf);
            return false;
        }
    }

    return false;
}

int response_attestation(Socket &socket) {
    std::vector<uint8_t> input_buf, output_buf;
    IASClient client("./ias_cert.pem");

    if (!handle_event(ATT_MSG0, socket, client)) {
        return -1;
    }

    if (!handle_event(ATT_MSG1, socket, client)) {
        return -1;
    }

    if (!handle_event(ATT_MSG3, socket, client)) {
        return -1;
    }

    return 0;
}

void handle_routine(Socket &socket) {
    if (response_attestation(socket)) {
        return;
    }

    int cmd_type;
    sgx_status_t status;
    int ret = 0;
    std::vector<uint8_t> input_buf, output_buf;

    socket.ReadCommand(cmd_type, input_buf);

    if (input_buf.empty() || (cmd_type == CMD_DECRYPT && input_buf.size() < 16)) {
        write_string("Input buffer too short or empty", output_buf);
        socket.WriteCommand(CMD_ERR, output_buf);
        return;
    }

    switch (cmd_type) {
    case CMD_ENCRYPT:
        output_buf.resize(input_buf.size() + 16);
        status = EnclaveAesEncryption(enclave_id, &ret, input_buf.data(), input_buf.size(), output_buf.data() + 16, output_buf.data());
        break;

    case CMD_DECRYPT:
        output_buf.resize(input_buf.size() - 16);
        status = EnclaveAesDecryption(enclave_id, &ret, input_buf.data() + 16, output_buf.size(), output_buf.data(), input_buf.data());
        break;

    case CMD_SET_KEY:
        status = SetAesKey(enclave_id, &ret, input_buf.data(), input_buf.size());
        /*{
            std::vector<uint8_t> buf;
            buf.resize(16);
            GetAesKey(enclave_id, &ret, buf.data(), 16);
            for (auto &v : buf) {
                printf("%c\n", (char) v);
            }
        }*/
        break;

    default:
        write_string("Invalid command", output_buf);
        socket.WriteCommand(CMD_ERR, output_buf);
        return;
    }

    if (status || ret) {
        char buf[1024];
        sprintf(buf, "Enclave function failed, status %X, ret %X", status, ret);
        write_string(buf, output_buf);
        socket.WriteCommand(CMD_ERR, output_buf);
        return;
    }

    socket.WriteCommand(cmd_type, output_buf);
}

int SGX_CDECL main(int argc, char **argv) {
    EnclaveLoader loader("enclave.signed.so", "enclave.token", 1);
    enclave_id = loader.enclave_id;
    parse_arguments(argc, argv);

    auto listener_fd = Socket::Listen(server_port);
    if (!listener_fd.Valid()) {
        exit(EXIT_FAILURE);
    }

    Listener listener(listener_fd);
    listener.Run(handle_routine);
    return 0;
}
