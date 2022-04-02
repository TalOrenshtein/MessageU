#include "respHdr.h"


respHdr::respHdr(char ver, unsigned short code, size_t payloadSize, char* pd) {
    version = ver;
    this->code = code;
    payload_size = payloadSize;
    payload = pd;
}
respHdr::respHdr(char ver, unsigned short code) {
    version = ver;
    this->code = code;
    payload_size = 0;
    payload = nullptr;
}
respHdr::respHdr(char* buff) { 
    char* bp = buff;
    version = *bp;
    bp++;
    memcpy(&code, bp, sizeof(short));
    code = (size_t)ntohs(code);
    bp += sizeof(short);
    memcpy(&payload_size, bp, sizeof(size_t));
    payload_size = (size_t)ntohl(payload_size);
    if (payload_size > 0)
        payload = new char[payload_size];
    else
        payload = nullptr;
}
respHdr::~respHdr() {
    delete[] payload;
}