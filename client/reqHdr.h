#ifndef REQHDR_H
#define REQHDR_H

#include <string>
#include <WinSock2.h> // needed to use htonl
#define UUIDlength 16
#define reqReg 100 
#define reqList 101
#define reqPubKey 102
#define reqSendMsg 103
#define reqPullMsgs 104

class reqHdr {
    char* clientID;
    char version;
    char code;
    unsigned int payload_size;
    const char* payload;
public:
    reqHdr(char* id, char ver, char code, unsigned int psize, const char* p);
    reqHdr(char* id, char ver, char code);
    const char* getClientID();
    char getVersion();
    char getCode();
    unsigned int getPayloadSize();
    const char* getPayload();
    size_t getLength();
    const char* getCharP();
};

#endif;