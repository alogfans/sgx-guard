//
// Created by alogfans on 8/13/17.
//

#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include "Socket.h"

SocketFd::~SocketFd() {
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

Socket& Socket::operator=(const Socket &rhs) {
    descriptor = rhs.descriptor;
    return *this;
}

Socket Socket::Listen(uint16_t port) {
    struct addrinfo *resolved_addr = nullptr, *iterator;
    char service[6];
    int sockfd = -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (sprintf(service, "%d", port) < 0){
        perror("sprintf");
        exit(EXIT_FAILURE);
    }

    if (getaddrinfo(NULL, service, &hints, &resolved_addr) < 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }

    for (iterator = resolved_addr; sockfd < 0 && iterator; iterator = iterator->ai_next) {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);

        if (sockfd < 0) {
            perror("sockfd");
            continue;
        }

        int on = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            perror("setsockopt");
            close(sockfd);
            sockfd = -1;
            continue;
        }

        if (bind(sockfd, iterator->ai_addr, iterator->ai_addrlen) < 0) {
            perror("bind");
            close(sockfd);
            sockfd = -1;
            continue;
        }

        if (listen(sockfd, 5) < 0) {
            perror("listen");
            close(sockfd);
            sockfd = -1;
        }
    }

    if (resolved_addr) {
        freeaddrinfo(resolved_addr);
    }

    return Socket(sockfd);
}

Socket Socket::Connect(const std::string &server_name, uint16_t port) {
    struct addrinfo *resolved_addr = nullptr, *iterator;
    char service[6];
    int on = 1;
    int sockfd = -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (sprintf(service, "%d", port) < 0){
        perror("sprintf");
        return Socket();
    }

    // Resolve DNS address
    if (getaddrinfo(server_name.c_str(), service, &hints, &resolved_addr) < 0) {
        perror("getaddrinfo");
        return Socket();
    }

    for (iterator = resolved_addr; sockfd < 0 && iterator != NULL; iterator = iterator->ai_next) {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);

        if (sockfd < 0) {
            perror("socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            perror("setsockopt");
            close(sockfd);
            sockfd = -1;
            continue;
        }

        if (connect(sockfd, iterator->ai_addr, iterator->ai_addrlen) < 0) {
            perror("connect");
            close(sockfd);
            sockfd = -1;
            continue;
        }
    }

    if (resolved_addr) {
        freeaddrinfo(resolved_addr);
    }

    return Socket(sockfd);
}

Socket Socket::Accept() {
    if (!Valid()) {
        return Socket();
    }

    int client_fd = accept(descriptor->Get(), NULL, 0);
    return Socket(client_fd);
}

int Socket::SetBlocking(bool blocking) {
    int flags = fcntl(descriptor->Get(), F_GETFL, 0);
    if (blocking) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }

    int rc = fcntl(descriptor->Get(), F_SETFL, flags);
    return rc;
}

bool Socket::Blocking() {
    int flags = fcntl(descriptor->Get(), F_GETFL, 0);
    return (flags & O_NONBLOCK) != 0;
}

ssize_t Socket::Read(void *buffer, size_t length) {
    if (!Valid())
        return -1;

    ssize_t nbytes, bytes_read = 0;
    while (bytes_read < length) {
        nbytes = read(descriptor->Get(), (uint8_t *) buffer + bytes_read, length - bytes_read);
        if (nbytes < 0) {
            if (errno == EINTR) {
                bytes_read = 0;
            } else {
                perror("read");
                return -1;
            }
        } else if (nbytes == 0) {
            break;
        }

        bytes_read += nbytes;
    }

    return bytes_read;
}

ssize_t Socket::Write(const void *buffer, size_t length) {
    if (!Valid())
        return -1;

    ssize_t nbytes, bytes_written = 0;
    while (bytes_written < length) {
        nbytes = write(descriptor->Get(), (uint8_t *) buffer + bytes_written, length - bytes_written);
        if (nbytes < 0) {
            if (errno == EINTR) {
                bytes_written = 0;
            } else {
                perror("write");
                return -1;
            }
        }

        bytes_written += nbytes;
    }

    return bytes_written;
}

std::string Socket::ReadLine() {
    size_t msg_length = 0;
    if (Read(&msg_length, sizeof(msg_length)) != sizeof(msg_length)) {
        return std::string();
    }

    char* strbuffer = new char[msg_length];
    memset(strbuffer, 0, msg_length);
    if (Read(strbuffer, msg_length) < 0) {
        delete(strbuffer);
        return std::string();
    }

    std::string str(strbuffer);
    delete(strbuffer);
    return str;
}

int Socket::WriteLine(const std::string &msg) {
    size_t msg_length = msg.size() + 1;
    if (Write(&msg_length, sizeof(msg_length)) != sizeof(msg_length)) {
        return -1;
    }

    if (Write(msg.c_str(), msg_length) < 0) {
        return -1;
    }

    return 0;
}

int Socket::ReadCommand(int &op, std::vector<uint8_t> &buf) {
    size_t msg_length = 0;
    if (Read(&msg_length, sizeof(msg_length)) != sizeof(msg_length)) {
        return -1;
    }

    if (msg_length < sizeof(int)) {
        return -1;
    }

    if (Read(&op, sizeof(int)) != sizeof(int)) {
        return -1;
    }

    buf.resize(msg_length - sizeof(int));

    if (Read(buf.data(), buf.size()) != buf.size()) {
        return -1;
    }

    return 0;
}

int Socket::WriteCommand(int op, const std::vector<uint8_t> &buf) {
    size_t msg_length = sizeof(int) + buf.size();
    if (Write(&msg_length, sizeof(msg_length)) != sizeof(msg_length)) {
        return -1;
    }

    if (Write(&op, sizeof(int)) != sizeof(int)) {
        return -1;
    }

    if (Write(buf.data(), buf.size()) != buf.size()) {
        return -1;
    }

    return 0;
}

void Listener::Run(CallbackFunction callback) {
    while (!terminate) {
        Socket target = socket.Accept();
        if (callback) {
            callback(target);
        }
    }
}
