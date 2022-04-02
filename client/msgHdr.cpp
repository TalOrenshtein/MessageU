#include "msgHdr.h"
#define UUIDlength 16

msgHdr::msgHdr(char* uuid, char type, size_t cSize, char* buff) {
    uid = uuid;
    msgType = type;
    content_size = cSize;
    msg = buff;
}
msgHdr::msgHdr(char* uuid, char type) {
    uid = uuid;
    msgType = type;
    content_size = 0;
    msg = nullptr;
}
size_t msgHdr::getContentSize() {
    return content_size;
}
/*Chains the header's fields as a one char array, and returns a pointer to the beginning.
 User needs to free the buffer after use.*/
const char* msgHdr::getCharP() {
    char* buff = new char[UUIDlength + sizeof(char) + sizeof(size_t) + content_size];
    char* bp = buff;
    memset(bp, '\0', UUIDlength + sizeof(char) + sizeof(size_t) + content_size);
    memcpy(bp, uid, UUIDlength);
    bp += UUIDlength;
    *bp = msgType;
    if (content_size > 0) {
        bp++;
        size_t ctSzNet = htonl(content_size);
        memcpy(bp, &ctSzNet, sizeof(size_t));
        bp += sizeof(size_t);
        memcpy(bp, msg, content_size);
    }
    return buff;
}