cmake_minimum_required(VERSION 3.10)
project(sgx_guard)

set(CMAKE_CXX_STANDARD 11)

include_directories(Client/App)
include_directories(Client/Enclave)
include_directories(Server/App)
include_directories(Server/Enclave)
include_directories(Shared)

add_executable(sgx_guard
        Client/App/App.cpp
        Client/App/RAClient.cpp
        Client/App/RAClient.h
        Client/Enclave/Enclave.cpp
        Client/Enclave/Enclave.h
        Server/App/App.cpp
        Server/App/base64.h
        Server/App/IASClient.cpp
        Server/App/IASClient.h
        Server/App/json.h
        Server/Enclave/Enclave.cpp
        Server/Enclave/Enclave.h
        Shared/CmdParser.h
        Shared/EnclaveLoader.cpp
        Shared/EnclaveLoader.h
        Shared/Socket.cpp
        Shared/Socket.h
        Server/App/RAServer.cpp
        Server/App/RAServer.h)
