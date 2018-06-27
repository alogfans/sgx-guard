//
// Created by alogfans on 6/27/18.
//

#ifndef SGX_GUARD_RASERVER_H
#define SGX_GUARD_RASERVER_H


#include <EnclaveLoader.h>
#include <vector>
#include <Socket.h>
#include "IASClient.h"

class RAServer {
public:
    RAServer(const EnclaveLoader &loader, IASClient &client, uint8_t *sgid);
    virtual ~RAServer() { }

    void Attest(Socket &socket, const std::vector<uint8_t> &msg0);

public:
    bool onMsg0Arrival(const std::vector<uint8_t> &msg0);
    bool onMsg1Arrival(const std::vector<uint8_t> &msg1, std::vector<uint8_t> &msg2);
    bool onMsg3Arrival(const std::vector<uint8_t> &msg3, std::vector<uint8_t> &msg4);

    void write_string(const std::string &str, std::vector<uint8_t> &buf);

private:
    const EnclaveLoader &loader;
    IASClient &client;
    uint8_t sgid[16];
};


#endif //SGX_GUARD_RASERVER_H
