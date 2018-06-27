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

#include "base64.h"
#include "RAServer.h"

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>

uint16_t server_port = 8080;

#define CMD_ENCRYPT 1
#define CMD_DECRYPT 2
#define CMD_SET_KEY 3
#define CMD_ERR     4
#define ATT_MSG0    100

EnclaveLoader loader("enclave.signed.so", "enclave.token", 1);
IASClient client("./ias_cert.pem");

uint8_t sgid[] = {0x19, 0x0D, 0x7D, 0xF5, 0x89, 0x64, 0x16, 0x6B,
                  0xE8, 0xD4, 0x48, 0x89, 0x22, 0x55, 0x90, 0x1D};

RAServer attest(loader, client, sgid);

void parse_arguments(int argc, char **argv) {
    CLI::App app{"SGX Guard Service"};
    app.add_option("-p,--port", server_port, "Tcp port that provide SGX Guard Service");

    try {
        app.parse(argc, argv);
    } catch (CLI::ParseError &e) {
        std::exit(app.exit(e));
    }
}

void write_string(const std::string &str, std::vector<uint8_t> &buf) {
    buf.clear();
    buf.resize(str.size() + 1);
    memcpy(buf.data(), str.c_str(), buf.size());
}

void handle_routine(Socket &socket) {
    int cmd_type;
    sgx_status_t ret, ret_call;
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
        ret = enclave_aes_encrypt(
                loader.enclave_id,
                &ret_call,
                input_buf.data(),
                input_buf.size(),
                output_buf.data() + 16,
                output_buf.data());

        break;

    case CMD_DECRYPT:
        output_buf.resize(input_buf.size() - 16);
        ret = enclave_aes_decrypt(
                loader.enclave_id,
                &ret_call,
                input_buf.data() + 16,
                output_buf.size(),
                output_buf.data(),
                input_buf.data());

        break;

    case ATT_MSG0:
        attest.Attest(socket, input_buf);
        break;

    case CMD_SET_KEY:
        ret = enclave_aes_key(loader.enclave_id, &ret, input_buf.data(), input_buf.size());
        break;

    default:
        write_string("Invalid command", output_buf);
        socket.WriteCommand(CMD_ERR, output_buf);
        return;
    }

    if (ret_call || ret) {
        char buf[1024];
        sprintf(buf, "Enclave function failed, ret %X, ret_call %X", ret, ret_call);
        write_string(buf, output_buf);
        socket.WriteCommand(CMD_ERR, output_buf);
        return;
    }

    socket.WriteCommand(cmd_type, output_buf);
}

int SGX_CDECL main(int argc, char **argv) {
    parse_arguments(argc, argv);

    auto listener_fd = Socket::Listen(server_port);
    if (!listener_fd.Valid()) {
        exit(EXIT_FAILURE);
    }

    Listener listener(listener_fd);
    listener.Run(handle_routine);
    return 0;
}
