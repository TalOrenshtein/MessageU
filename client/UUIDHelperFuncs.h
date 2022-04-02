#ifndef UUIDHELPERFUNCS_H
#define UUIDHELPERFUNCS_H

#include "WSA.h"
#pragma comment(lib, "rpcrt4.lib")  // UuidCreate funcion
#include <iostream>
#define UUIDlength 16

inline const unsigned char* UUIDtoByteArray(const UUID& g) {
    return reinterpret_cast<const unsigned char*>(&g);
}
inline const UUID& ByteArraytoUUID(const unsigned char* a) {
    return reinterpret_cast<const UUID&>(*a);
}
// user need to delete the returned char* after usage.
inline const char* UUIDbyteArrayToString(const unsigned char* uuid) {
    char* str = new char[37];
    memset(str, 0, 37);
    unsigned long data1 = *reinterpret_cast<const unsigned long*>(uuid);
    unsigned short data2 = *reinterpret_cast<const unsigned short*>(uuid + 4);
    unsigned short data3 = *reinterpret_cast<const unsigned short*>(uuid + 6);
    sprintf_s(str, 37,
        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        data1, data2, data3,
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );
    return (const char*)str;
}
inline bool uuidIsNilSTR(std::string& str) {
    return str == std::string("00000000-0000-0000-0000-000000000000");
}
#endif;