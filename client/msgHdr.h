#ifndef MSGHDR_H
#define MSGDR_H

#include <string>
#include <WinSock2.h> // needed to use htonl

#ifndef MSGCODE
#define MSGCODE
#define msgHdr_SizeBeforePL 21
#define msgTypeSymSend 2
#define msgTypeSymReq 1
#define msgTypeText 3
#endif;

class msgHdr {
    char* uid;
    char msgType;
    size_t content_size;
    char* msg;
public:
    msgHdr(char* uuid, char type, size_t cSize, char* buff);
    msgHdr(char* uuid, char type);
    size_t getContentSize();
    const char* getCharP();
};
#endif;