//
// Created by alogfans on 6/11/18.
//

#ifndef EXAMPLE_IASCLIENT_H
#define EXAMPLE_IASCLIENT_H

#include <string>
#include <restclient-cpp/connection.h>

class IASClient {
public:
    explicit IASClient(const std::string &cert_path = "");
    ~IASClient();

    bool retrieveSigRL(const std::string &gid, std::string &sigRL);

    std::map<std::string, std::string> report(const std::string &isvEnclaveQuote,
                                              const std::string &pseManifest = "",
                                              const std::string &nonce = "");

private:
    RestClient::Connection* conn;
};


#endif //EXAMPLE_IASCLIENT_H
