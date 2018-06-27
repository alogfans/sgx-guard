//
// Created by alogfans on 6/11/18.
//

#include <restclient-cpp/restclient.h>
#include <sstream>
#include "IASClient.h"
#include "json.h"

using json = nlohmann::json;

IASClient::IASClient(const std::string &cert_path) {
    RestClient::init();
    conn = new RestClient::Connection("https://test-as.sgx.trustedservices.intel.com:443/");
    conn->SetTimeout(5);
    if (!cert_path.empty()) {
        conn->SetCertPath(cert_path);
    }
}


IASClient::~IASClient() {
    RestClient::disable();
}

bool IASClient::retrieveSigRL(const std::string &gid, std::string &sigRL) {
    RestClient::Response response = conn->get("/attestation/sgx/v2/sigrl/" + gid);
    if (response.code != 200) {
        printf("retrieveSigRL failed. Response code %d\n", response.code);
        return false;
    }

    sigRL = response.body;
    return true;
}

std::map<std::string, std::string> IASClient::report(const std::string &isvEnclaveQuote,
                                                     const std::string &pseManifest,
                                                     const std::string &nonce) {

    std::map<std::string, std::string> ret;

    json input;
    input["isvEnclaveQuote"] = isvEnclaveQuote;
    if (!pseManifest.empty()) {
        input["pseManifest"] = pseManifest;
    }
    if (!nonce.empty()) {
        input["nonce"] = nonce;
    }

    RestClient::Response response = conn->post("/attestation/sgx/v2/report", input.dump(4));

    if (response.code != 200) {
        printf("report failed. response code %d\n", response.code);
        return ret;
    }

    for (auto &v : response.headers) {
        ret[v.first] = v.second;
    }    

    json output = json::parse(response.body);

    for (json::iterator it = output.begin(); it != output.end(); ++it) {
        ret[it.key()] = it.value();
    }

    return ret;
}

