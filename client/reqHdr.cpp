#include "reqHdr.h"

reqHdr::reqHdr(char* id, char ver, char code, unsigned int psize, const char* p) {
    clientID = id;
    version = ver;
    this->code = code;
    payload_size = psize;
    payload = p;
}
const char* reqHdr::getClientID() {
    return clientID;
}
char reqHdr::getVersion() {
    return version;
}
char reqHdr::getCode() {
    return code;
}
unsigned int reqHdr::getPayloadSize() {
    return payload_size;
}
const char* reqHdr::getPayload() {
    return payload;
}
size_t reqHdr::getLength() {
    return UUIDlength + sizeof(version) + sizeof(code) + sizeof(payload_size) + payload_size;
}
/*Chains the header's fields as a one char array, and returns a pointer to the beginning.
 User need to free the buffer after use.*/
const char* reqHdr::getCharP() {
    char* buff = new char[UUIDlength + sizeof(version) + sizeof(code) + sizeof(payload_size) + payload_size]; // includes null terminate char.
    memset(buff, '\0', UUIDlength + sizeof(version) + sizeof(code) + sizeof(payload_size) + payload_size);
    char* bp = buff;
    memcpy(bp, clientID, UUIDlength);
    bp += UUIDlength;
    *bp = version;
    bp += sizeof(version);
    *bp = code;
    if (payload_size > 0) {
        bp += sizeof(code);
        size_t payloadNet = htonl(payload_size);
        memcpy(bp, &payloadNet, sizeof(size_t));
        bp += sizeof(payload_size);
        memcpy(bp, payload, payload_size);
    }
    return buff;
}