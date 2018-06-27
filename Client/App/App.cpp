#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sgx_key_exchange.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include "sgx_urts.h"

#include "CmdParser.h"
#include "EnclaveLoader.h"

#include "Enclave_u.h"
#include "Socket.h"
#include "RAClient.h"

std::string server_host = "localhost";
uint16_t server_port = 8080;


#define CMD_ENCRYPT 1
#define CMD_DECRYPT 2
#define CMD_SET_KEY 3
#define CMD_ERR     4

int cmd_type;
std::string plain_path, cipher_path;

std::string plain_aes_key_str;
uint8_t plain_aes_key[16];

void parse_arguments(int argc, char **argv) {
    CLI::App app{"SGX Client"};
    app.add_option("-s,--server", server_host, "Host of SGX Guard Service provider");
    app.add_option("-p,--port", server_port, "Tcp port that provide SGX Guard Service");

    auto encrypt_cmd = app.add_subcommand("encrypt", "Encrypt a local file");
    encrypt_cmd->add_option("--plain", plain_path, "Plain document path")->required(true);
    encrypt_cmd->add_option("--cipher", cipher_path, "Cipher document path")->required(true);
    auto decrypt_cmd = app.add_subcommand("decrypt", "Decrypt a local file");
    decrypt_cmd->add_option("--plain", plain_path, "Plain document path")->required(true);
    decrypt_cmd->add_option("--cipher", cipher_path, "Cipher document path")->required(true);
    auto setkey_cmd = app.add_subcommand("config", "Config with AES key");
    setkey_cmd->add_option("--aes-key", plain_aes_key_str, "AES key, should be represented as hex literal (16 bytes)")->required(true);

    app.require_subcommand(1);

    try {
        app.parse(argc, argv);
    } catch (CLI::ParseError &e) {
        std::exit(app.exit(e));
    }

    if (*encrypt_cmd) {
        cmd_type = CMD_ENCRYPT;
    } else if (*decrypt_cmd) {
        cmd_type = CMD_DECRYPT;
    } else if (*setkey_cmd) {
        cmd_type = CMD_SET_KEY;
    }
}

void read_all(const std::string &path, std::vector<uint8_t> &buf) {
    struct stat st;
    if (stat(path.c_str(), &st)) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    buf.resize(st.st_size);
    if (read(fd, buf.data(), buf.size()) != buf.size()) {
        perror("read");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}

void write_all(const std::string &path, const std::vector<uint8_t> &buf) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if (write(fd, buf.data(), buf.size()) != buf.size()) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}

bool build_aes_key() {
    if (plain_aes_key_str.size() != 32) {
        printf("error: illegal aes_key: should be exact 16 bytes like '00112233445566778899AABBCCDDEEFF'\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 16; i++) {
        plain_aes_key[i] = 0;
        for (int k = 0 ; k < 2; k++) {
            char ch = plain_aes_key[i * 2 + k];
            if (ch >= '0' && ch <= '9') {
                plain_aes_key[i] = plain_aes_key[i] * 16 + ch - '0';
            } else if (ch >= 'A' && ch <= 'F') {
                plain_aes_key[i] = plain_aes_key[i] * 16 + ch - 'A';
            } else if (ch >= 'a' && ch <= 'f') {
                plain_aes_key[i] = plain_aes_key[i] * 16 + ch - 'a';
            } else {
                printf("error: illegal aes_key: should be exact 16 bytes like '00112233445566778899AABBCCDDEEFF'\n");
                exit(EXIT_FAILURE);
            }
        }
    }
}

EnclaveLoader loader("enclave.signed.so", "enclave.token", 1);
RAClient attest(loader);

int SGX_CDECL main(int argc, char **argv) {
    parse_arguments(argc, argv);

    auto socket = Socket::Connect(server_host, server_port);
    if (!socket.Valid()) {
        exit(EXIT_FAILURE);
    }

    std::vector<uint8_t> data_stream;

    if (cmd_type == CMD_SET_KEY) {
        build_aes_key();
        attest.Attest(socket);

        int sealed_size = 0;
        sgx_status_t ret, ret_call;
        enclave_seal_size(loader.enclave_id, &sealed_size, 16);
        data_stream.resize(sealed_size);
        ret = enclave_seal_aes_key(loader.enclave_id, &ret_call, plain_aes_key, sealed_size, data_stream.data());
        if (ret || ret_call) {
            printf("enclave_seal_aes_key error %x %x\n", ret, ret_call);
            return EXIT_FAILURE;
        }

    } else if (cmd_type == CMD_ENCRYPT) {
        read_all(plain_path, data_stream);
    } else if (cmd_type == CMD_DECRYPT) {
        read_all(cipher_path, data_stream);
    }

    int cmd_type_ret;
    socket.WriteCommand(cmd_type, data_stream);

    data_stream.clear();
    socket.ReadCommand(cmd_type_ret, data_stream);

    if (cmd_type_ret == CMD_ERR) {
        const char *str_buf = (const char *) data_stream.data();
        printf("Error: %s\n", str_buf);
        return EXIT_FAILURE;
    }

    if (cmd_type == CMD_ENCRYPT) {
        write_all(cipher_path, data_stream);
    } else if (cmd_type == CMD_DECRYPT) {
        write_all(plain_path, data_stream);
    }

    printf("Success!\n");

    return 0;
}
