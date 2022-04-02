#include "msgRespHdr.h"

//opens the buffer to the header's fields while following the protocol.
msgRespHdr::msgRespHdr(char* buff) {
    char* bp = buff;
    memcpy(UUID, bp, UUIDlength);
    bp += UUIDlength;
    memcpy(&MessageID, bp, sizeof(size_t));
    MessageID = (size_t) ntohl(MessageID);
    bp += sizeof(size_t);
    MessageType = *bp;
    bp += sizeof(char);
    memcpy(&Message_Size, bp, sizeof(size_t));
    Message_Size = (size_t)ntohl(Message_Size);
    if (Message_Size > 0)
        content = new char[Message_Size];
}
msgRespHdr::~msgRespHdr() {
    delete[] content;
}