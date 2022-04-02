#ifndef CLIENT_H
#define CLIENT_H

#include "UUIDHelperFuncs.h"
#include "customAES.h"
#include "customRSA.h"
#include "reqHdr.h"
#include "respHdr.h"
#include "msgHdr.h"
#include "msgRespHdr.h"
#include "customException.h"

#include <vector>

#define MaxNameLenth 255
#define clientVersion '1'

class client {
    void initSockAndConnect();
public:
    SOCKET s;
    char* uid; // client's UUID
    std::string username; // client's username
    struct sockaddr_in sa = { 0 };
    std::pair<std::string, char*>* RSAkeys; //RSAkeys.first is the secret key,RSAkeys.second is the public key.
    std::map<std::string,char*> symKeys; // A map with a string representation of a UUID as key and char* of a symmetric key as a value.
    std::map<std::string, char*> pubKeys;// A map with a string representation of a UUID as key and char* of a public key as a value.
    client();
    client(std::pair<std::string, char*>* rsa, char* uuid,std::string un);
    ~client();
    SOCKET* getSocket();
    int sendHdr(reqHdr* hdr);
    respHdr* createRespHdr(char code, unsigned int plSize,const char* pl);
    std::map<std::string, std::string>* getUsersMap();
    uuid_t findUUID(const std::string& username);
    std::string findUUIDStr(const std::string& username);
    bool getPublicKey(const std::string& username);
    std::string findUsername(const std::string& uid); // not in use right now.
    long long sendMsg(char msgType);
    bool registerClient(std::string& username);
    void pullMsgs();
    static bool isUsernameLegal(std::string& username);
    static void chooseLegalUsername(std::string& username);
};

#endif;