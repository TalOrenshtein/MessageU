#ifndef MSGRESPHDR_H
#define MSGRESPHDR_H

#include <string>
#include <WinSock2.h> //needed to use ntohl

#define UUIDlength 16
#define msgRespHdr_SizeBeforePL 25
#ifndef MSGCODE
#define MSGCODE
#define msgHdr_SizeBeforePL 21
#define msgTypeSymSend 2
#define msgTypeSymReq 1
#define msgTypeText 3
#endif;

class msgRespHdr {
public:
    char UUID[UUIDlength];
    size_t MessageID;
    char MessageType;
    size_t Message_Size;
    char* content = nullptr;
    msgRespHdr(char* buff);
    ~msgRespHdr();
};

#endif;