#ifndef WSA_H
#define WSA_H

#include <WinSock2.h>
#include <windows.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")

class WSA {
public:
    WSA() {
        WSADATA wsaData;
        int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
    ~WSA() {
        WSACleanup();
    }
};
#endif;

