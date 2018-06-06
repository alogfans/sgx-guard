//
// Created by alogfans on 8/13/17.
//

#ifndef RIO_SOCKET_H
#define RIO_SOCKET_H


#include <sys/socket.h>
#include <memory>
#include <functional>
#include <atomic>
#include <vector>

class SocketFd {
public:
    SocketFd(int fd = -1) : fd(fd) { }
    int Get() { return fd; }
    ~SocketFd();

    SocketFd(const SocketFd&) = delete;
    SocketFd& operator= (const SocketFd&) = delete;

private:
    int fd;
};

class Socket {
public:
    Socket(int fd = -1) : descriptor(new SocketFd(fd)) { }
    ~Socket() { }

    Socket(const Socket& rhs) : descriptor(descriptor) { }
    Socket& operator= (const Socket& rhs);

    static Socket Listen(uint16_t port);
    static Socket Connect(const std::string& server_name, uint16_t port);

    bool Valid() { return descriptor->Get() >= 0; }
    int Get() { return descriptor->Get(); }
    int SetBlocking(bool blocking);
    bool Blocking();

    Socket Accept();
    ssize_t Read(void *buffer, size_t length);
    ssize_t Write(const void *buffer, size_t length);

    std::string ReadLine();
    int WriteLine(const std::string &msg);

    int WriteCommand(int op, const std::vector<uint8_t> &buf);
    int ReadCommand(int &op, std::vector<uint8_t> &buf);

private:
    std::shared_ptr<SocketFd> descriptor;
};

class Listener {
public:
    using CallbackFunction = std::function<void(Socket &)>;
    Listener(Socket &socket) : socket(socket), terminate(false) { }
    ~Listener() { terminate.store(true); }

    void Run(CallbackFunction callback);
    void Shutdown() { terminate.store(true); }

private:
    Listener(const Listener&) = delete;
    Listener& operator= (const Listener&) = delete;

private:
    Socket &socket;
    std::atomic<bool> terminate;
};

#endif //RIO_SOCKET_H