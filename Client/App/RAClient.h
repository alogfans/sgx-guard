//
// Created by alogfans on 6/5/18.
//

#ifndef GUARD_ATTESTER_H
#define GUARD_ATTESTER_H

#include "EnclaveLoader.h"
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "Socket.h"

class RAClient {
public:
    RAClient(const EnclaveLoader &loader);
    virtual ~RAClient();

    void Attest(Socket &socket);

public:
    void buildMsg0(std::vector<uint8_t> &msg0);
    void buildMsg1(std::vector<uint8_t> &msg1);
    void buildMsg3(const std::vector<uint8_t> &msg2, std::vector<uint8_t> &msg3);

private:
    uint32_t epid_group_id;
    uint32_t ra_context;
    const EnclaveLoader &loader;
};


#endif //GUARD_ATTESTER_H
