//
// Created by alogfans on 6/5/18.
//

#ifndef GUARD_ATTESTER_H
#define GUARD_ATTESTER_H

#include "EnclaveLoader.h"
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "Socket.h"

class Attester {
public:
    Attester(const EnclaveLoader &loader);
    virtual ~Attester();

    void Attest(Socket &socket);

private:
    void buildMsg0(std::vector<uint8_t> &msg);
    void buildMsg1(std::vector<uint8_t> &msg);
    void buildMsg3(const std::vector<uint8_t> &recv_msg2, std::vector<uint8_t> &msg);

private:
    uint32_t epid_group_id;
    uint32_t ra_context;
    const EnclaveLoader &loader;
};


#endif //GUARD_ATTESTER_H
