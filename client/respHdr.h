#ifndef RESPHDR_H
#define RESPHDR_H

#include <WinSock2.h> // needed to use ntohs and ntohl.
#include <cstdlib>
#include <string>

#define respHdrSizeBeforePL 7 // version (1bit),code(2bits),payload size(unsigned int).
#define respSucReg 1000
#define respUsersList 1001
#define respPubKey 1002
#define respSucMsg 1003
#define respPullMsgs 1004
#define respErr 9000

class respHdr {
public:
    char version;
    unsigned short code;
    size_t payload_size;
    char* payload;
    respHdr(char ver, unsigned short code, size_t payloadSize, char* pd);
    respHdr(char ver, unsigned short code);
    respHdr(char* buff);
    ~respHdr();
};

#endif;