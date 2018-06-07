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

#include "service_provider.h"

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
    buf.resize(str.size());
    memcpy(buf.data(), str.c_str(), buf.size());
}

int response_attestation(Socket &socket) {
    int cmd_type;
    sgx_status_t status;
    int ret = 0;
    std::vector<uint8_t> input_buf, output_buf;

    socket.ReadCommand(cmd_type, input_buf);
    if (cmd_type != ATT_MSG0) {
        write_string("wrong message", output_buf);
        socket.WriteCommand(ATT_ERR, output_buf);
        return -1;
    }

    if (sp_ra_proc_msg0_req((const sample_ra_msg0_t *) input_buf.data(), input_buf.size())) {
        write_string("attestation 0 fault", output_buf);
        socket.WriteCommand(ATT_ERR, output_buf);
        return -1;
    }    

    socket.WriteCommand(ATT_MSG0, output_buf);

    socket.ReadCommand(cmd_type, input_buf);
    if (cmd_type != ATT_MSG1) {
        write_string("wrong message", output_buf);
        socket.WriteCommand(ATT_ERR, output_buf);
        return -1;
    }

    ra_samp_response_header_t *p_msg2, *p_result;
    if (sp_ra_proc_msg1_req((const sample_ra_msg1_t *) input_buf.data(), input_buf.size(), &p_msg2)) {
        write_string("attestation 1 fault", output_buf);
        socket.WriteCommand(ATT_ERR, output_buf);
        return -1;
    }

    output_buf.resize(p_msg2->size);
    memcpy(output_buf.data(), p_msg2->body, output_buf.size());
    socket.WriteCommand(ATT_MSG2, output_buf);

    socket.ReadCommand(cmd_type, input_buf);
    if (cmd_type != ATT_MSG3) {
        write_string("wrong message", output_buf);
        socket.WriteCommand(ATT_ERR, output_buf);
        return -1;
    }

    if (sp_ra_proc_msg3_req((const sample_ra_msg3_t *) input_buf.data(), input_buf.size(), &p_result)){
        write_string("attestation 3 fault", output_buf);
        socket.WriteCommand(ATT_ERR, output_buf);
        return -1;
    }

    output_buf.resize(p_result->size);
    memcpy(output_buf.data(), p_result->body, output_buf.size());
    socket.WriteCommand(ATT_MSG3, output_buf);

/*
    socket.ReadCommand(cmd_type, input_buf);
    if (cmd_type != ATT_CONFIRM) {
        write_string("wrong message", output_buf);
        socket.WriteCommand(ATT_ERR, output_buf);
        return -1;
    }

    if (sp_ra_proc_msg_tpm_attest_confirm((tpm_enc_att_state_response_message_t *) input_buf.data(), input_buf.size())) {
        return -1;
    }
*/

    free(p_msg2);
    // free(p_result);

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
