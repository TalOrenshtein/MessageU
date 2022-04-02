#include "client.h"
void client::initSockAndConnect() {
    std::ifstream in("server.info");
    if (in.fail())
        throw customException("An error occured while accessing server.info file");
    std::string iport;
    getline(in, iport);
    std::string ip;
    u_short port;
    size_t portColonPos = iport.find(':');
    ip = iport.substr(0, portColonPos);
    port = (u_short)std::stoi(iport.substr(portColonPos+1));
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr.s_addr);
    sa.sin_port = htons(port);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0)
        throw customException("Connection to " + ip + ":" + std::to_string(port) + " failed.");
}
client::client() {
    try { initSockAndConnect(); }
    catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        throw customException("An error occured while connecting to the server.\n");
    }
    RSAkeys=customRSA::GenKeyPair();
    uuid_t uuid;
    if (UuidCreateNil(&uuid) != RPC_S_OK)
        throw customException("An error occured while creating nil UUID.");
    const unsigned char* uuidBA=UUIDtoByteArray(uuid);
    /* uuidBA is a reinterpret of a local uuid_t, so the memory that uuidBA points at will be "deleted".
    So, we copy the content that's in the memory uuidBA points at, that is, the uuid, to a place we reserve memory at.*/
    char* buff = new char[UUIDlength];
    memcpy(buff, uuidBA, UUIDlength);
    this->uid = buff;
}
client::client(std::pair<std::string, char*>* rsa, char* uuid,std::string un) {
    try { initSockAndConnect(); }
    catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        throw customException("An error occured while connecting to the server.\n");
    }
    uid = new char[UUIDlength];
    memcpy(uid, uuid, UUIDlength); //Sets the uid field
    username = un;
    RSAkeys = rsa;
}
client::~client() {
    closesocket(s);
    /*customAES::staticGenerate_key allocates memory on the heap and returns a pointer to it, So here we free the allocated memory.*/
    for (std::pair<std::string, char*> e : symKeys) {
        char* keyHolder = symKeys[e.first];
        delete[] keyHolder;
    }
    symKeys.clear();
    /*The public keys that been generated or loaded at customRSA class are allocating memory on the heap, so we free the allocated memory.*/
    for (std::pair<std::string, char*> e : pubKeys) {
        char* keyHolder = pubKeys[e.first];
        delete[] keyHolder;
    }
    pubKeys.clear();
    delete[] RSAkeys->second;
    delete RSAkeys;
    delete[] uid;
}
SOCKET* client::getSocket() {
    return &s;
}
//Checks if username stands some criteria.
bool client::isUsernameLegal(std::string& username) {
    if (username == "")
        return false;
    for (char e : username)
        if (!std::isdigit(e) && !std::islower(e) && !std::isupper(e))
            return false;
    return true;
}
//Sets the reference username to be a legal username.
void client::chooseLegalUsername(std::string& username) {
    while (username == "") {
        std::cin >> username;
        username = username.substr(0, MaxNameLenth);
        if (!isUsernameLegal(username)) {
            username = "";
            std::cout << "Username can only contain English letters and numbers. Please choose a valid username.\n? " << std::endl;
        }
        if (username == "")
            continue;
    }
}
//Sends a request header to the server, returns the number of bytes sent.
int client::sendHdr(reqHdr* hdr) {
    const char* buff = hdr->getCharP();
    size_t byteSent = send(s, buff, hdr->getLength(), 0);
    delete[] buff;
    if (hdr->getLength() != byteSent)
        throw customException("An error occured while sending the request header.");
    return byteSent;
}
/*Creates a request header using the parameters, receives a response header from the server and returns it if no error occurred.
  User needs to delete the respHdr after usage.*/
respHdr* client::createRespHdr(char code, unsigned int plSize = 0, const char* pl = nullptr) {
    //Using this method, you can easily implement new features and add them.
    unsigned short respExpectedCode =respErr; //it should NEVER stay as respErr after that switch below.
    switch (code) {
    case reqReg: {
        respExpectedCode =respSucReg;
        break;
    }
    case reqList: {
        respExpectedCode =respUsersList;
        break;
    }
    case reqPubKey: {
        respExpectedCode =respPubKey;
        break;
    }
    case reqSendMsg: {
        respExpectedCode =respSucMsg;
        break;
    }
    case reqPullMsgs: {
        respExpectedCode =respPullMsgs;
        break;
    }
    default: {
        throw customException("Invalid code parameter.");
    }
    }
    reqHdr req(uid, clientVersion, code, plSize, pl);
    sendHdr(&req);
    char buff[respHdrSizeBeforePL];
    if (recv(*getSocket(), buff, respHdrSizeBeforePL, 0) < 0)
        throw customException("An error occured while receiving the response header.");
    respHdr* resp = new respHdr(buff);
    if (resp->code != respExpectedCode)
        throw customException("An error occured: Response header's code is different than expected\nExpected: " + std::to_string(respExpectedCode) + "\nCode received is: " + std::to_string(resp->code));
    if (resp->payload_size > 0) {
        /*Each function will handle the situation that pl size is 0 differently.
        Just let each func check it on their own and handle it the way it should.*/
        if (recv(*getSocket(), resp->payload, resp->payload_size, 0) != resp->payload_size) {
            throw customException("An error occured while receiving the payload.");
        }
    }
    return resp;
}
/*Requests users list from the server and inserting it to a (uid,name) map.
 User needs to delete std::map after usage.*/
std::map<std::string, std::string>* client::getUsersMap() {
    respHdr* resp = createRespHdr(reqList);
    std::map<std::string, std::string>* userList = new std::map<std::string, std::string>;
    char* buff = resp->payload;
    //When a user list is requested, the server returns the list of a name,UUID for each user registered, so we iterate on each user.
    for (size_t i = 0; i < resp->payload_size / (MaxNameLenth + UUIDlength); i++) {
        unsigned char uidB[UUIDlength] = { '\0' };
        memcpy(uidB, buff, UUIDlength);
        buff += UUIDlength;
        const char* uid = UUIDbyteArrayToString(uidB);
        userList->insert(std::pair<std::string, std::string>((std::string)uid, (std::string)buff));
        delete[] uid;
        buff += MaxNameLenth; //sets buff to next user.
    }
    delete resp;
    return userList;
}
/*Finds a UUID of a user with a specifc username, and return a UUID object. Returns NIL UUID if username doesn't register to the server.
  We can implement it directly and loop only once on all the users instead of twice (one time at getUsersMap), but both has a time complexity of O(n) So I decided to reuse my code instead.*/
uuid_t client::findUUID(const std::string& username) {
    uuid_t uid;
    bool usernameFound = false;
    //using getUsersMap to iterate on all the registered users and find the one with the desired username.
    std::map<std::string, std::string>* m = getUsersMap();
    for (std::pair<std::string, std::string> e : *m) {
        if (e.second == username) {
            const char* uuidST = e.first.c_str();
            usernameFound = true;
            if (UuidFromStringA((RPC_CSTR)uuidST, &uid) != RPC_S_OK)
                throw customException("An error occured while recovering the UUID.");
            break;
        }
    }
    delete m;
    if (!usernameFound) {
        if (UuidCreateNil(&uid) != RPC_S_OK)
            throw customException("An error occured while creating nil UUID.");
    }
    return uid;
}
/*Finds a UUID of a user with a specifc username, and return UUID representation as a string. Returns the representation of a NIL UUID if a username doesn't register to the server.
  We can implement it directly and loop only once on all the users instead of twice (one time at getUsersMap), but both has a time complexity of O(n) So I decided to reuse my code instead.*/
std::string client::findUUIDStr(const std::string& username) {
    //using getUsersMap to iterate on all the registered users and find the one with the desired username.
    std::map<std::string, std::string>* m = getUsersMap();
    std::string uuid= std::string("00000000-0000-0000-0000-000000000000"); //in case the username isn't exist.
    for (std::pair<std::string, std::string> e : *m) {
        if (e.second == username) {
            uuid = e.first;
            break;
        }
    }
    delete m;
    return uuid;
}
//Requests username's public key and insert it to the pubKey map. Returns true only if the requested public key is received.
bool client::getPublicKey(const std::string& username) {
    if (username == this->username) {
        std::cout << "You don't need to ask for your public key, you have nothing to do with it ;)." << std::endl;
        return false;
    }
    uuid_t uuid = findUUID(username);
    RPC_STATUS rpcs;
    if (UuidIsNil(&uuid, &rpcs) && rpcs == RPC_S_OK) {
        throw customException("There is no user with that username that is registered to the server.");
    }
    respHdr* resp = createRespHdr(reqPubKey, UUIDlength, (const char*)(UUIDtoByteArray(uuid))); // The payload contains target-user's UUID of the targt user and his public key.
    if (resp->payload_size != UUIDlength+ publicKeyLength) {
        throw customException("An error occured while receiving the public key.");
    }
    unsigned char recvUUID[UUIDlength] = { '\0' };
    char* publicKey = new char[publicKeyLength];
    memset(publicKey, '\0', publicKeyLength);
    char* payloadP = resp->payload;
    memcpy(recvUUID, payloadP, UUIDlength);
    payloadP += UUIDlength;
    //checks if the server sent the public key of the right user.
    uuid_t targetUUID=ByteArraytoUUID(recvUUID);
    if (UuidCompare(&targetUUID, &uuid, &rpcs) != 0 || rpcs != RPC_S_OK)
        throw customException("An error occured while receiving public key.");
    const char* uuidSt = UUIDbyteArrayToString((const unsigned char*)recvUUID);
    memcpy(publicKey, payloadP, publicKeyLength);
    std::string targetUID(uuidSt);
    delete[] uuidSt;
    delete resp;
    pubKeys.insert(std::pair<std::string, char*>(targetUID, publicKey));
    return true;
}
/* Finds the username of the user that his UUID is uid and returns it. Returns an empty string if the UUID isn't in use by any user registered to the server.
We can implement it directly and loop only once on all the users instead of twice(one time at getUsersMap), but both has a time complexity of O(n) So I decided to reuse my code instead.*/
std::string client::findUsername(const std::string& uid) {
    std::string username="";
    std::map<std::string, std::string>* m = getUsersMap();
    if (m->find(uid) != m->end())
        username=m->at(uid);
    delete m;
    return username;
}
/*Sends a message of type msgType to a user that the client chooses. Returns -2 on general error (and prints the error),
 and returns -1 if the message has been send to a different user for some reason. Note that in case msgType=msgTypeSymSend, we delete the symmetric key we just entered.*/
long long client::sendMsg(char msgType) {
    std::string username="";
    std::cout << "Enter a username\n? ";
    chooseLegalUsername(username);
    username = username.substr(0, MaxNameLenth);
    if (username == this->username) {
        std::cout << "You canno't send message to yourself." << std::endl;
        return -2;
    }
    std::string targetUuidStr = findUUIDStr(username);
    if (uuidIsNilSTR(targetUuidStr)) {
        std::cout << "This username isn't registered to the server." << std::endl;
        return -2;
    }
    //converting the uuid in string form to byte array form so we can use it in headers.
    uuid_t targetUUID;
    if (UuidFromStringA((RPC_CSTR)targetUuidStr.c_str(), &targetUUID) != RPC_S_OK)
        throw customException("An error occured while sending a message.");
    const unsigned char* targetUUIDBytes = UUIDtoByteArray(targetUUID);
    const char* mHdrBuff; // Will hold the charP representation of the msgHdr that will be created.
    size_t payloadSize = msgHdr_SizeBeforePL;
    switch (msgType) {
    case msgTypeSymSend: {
        //Checks if the user got the public key of the target user, insert it at the symKeys map, encrypt the message and prepare a message header.
        if (pubKeys.find(targetUuidStr) == pubKeys.end()) {
            std::cout << "You need to get the user's public key before sending him the symmetric key." << std::endl;
            return -2;
        }
        symKeys.insert(std::pair<std::string, char*>(targetUuidStr, customAES::staticGenerate_key()));
        std::string msg = customRSA::encrypt(pubKeys[targetUuidStr], symKeys[targetUuidStr]);
        msgHdr mHdr((char*)targetUUIDBytes, msgTypeSymSend, msg.size(), (char*)msg.c_str());
        payloadSize += mHdr.getContentSize();
        mHdrBuff = mHdr.getCharP();
        break;
    }
    case msgTypeText: {
        //Checks if the user has the symmetric key of the target user, get a text message from the user, encrypt it and prepare a message header.
        if (symKeys.find(targetUuidStr) == symKeys.end()) {
            std::cout << "No symmetric key that related to " << username << " has been found. Please get a symmetric key before messaging." << std::endl;
            return -2;
        }
        std::string msg="";
        do {
            std::cout << "Enter a text message\n? ";
            std::cin >> msg;
            if(msg=="")
                std::cout << "The message cannot be empty. " << std::endl;
        } while (msg == "");
        std::string chiper = customAES::createChiper(symKeys[targetUuidStr], msg);
        // we are using c style string, so we're counting the null terminate char too
        msgHdr mHdr((char*)targetUUIDBytes, msgTypeText, chiper.size(), (char*)chiper.c_str());
        payloadSize+= mHdr.getContentSize(); 
        mHdrBuff = mHdr.getCharP();
        break;
    }
    case msgTypeSymReq: {
        msgHdr mHdr((char*)targetUUIDBytes, msgTypeSymReq);
        mHdrBuff = mHdr.getCharP();
        break;
    }
    default: {
        throw customException("Unexpected message code received as a parameter.");
    }
    }
    respHdr* resp = createRespHdr((char)reqSendMsg, payloadSize, mHdrBuff); //the payload contains the target-user's UUID and a 4-bytes that represents a positive message ID.
    //Verifies that the response header payload's size is the size of a UUID + the size of an uint (because of those 4-bytes that represents a positive message ID at the payload.)
    if (resp->payload_size != UUIDlength+sizeof(size_t)) {
        throw customException("An error occured while receiving a message ID from the server.");
    }
    /*checking if the UUID the we received from the server is matching our target user's UUID, meaning that
    the message has been sent to the right user.*/
    uuid_t uid = ByteArraytoUUID((const unsigned char*)resp->payload);
    RPC_STATUS rpcs;
    if (UuidCompare(&targetUUID, &uid, &rpcs) != 0) {
        /* Theres nothing much to do here, the sever already sent the message to some other user.
        but theres no reason to throw an error or something like that, if the message wasn't meant to send a
        symmetric key, we don't even need to a thing, because its e2ee.*/
        if (msgType == msgTypeSymSend) {
            /*because we can't know what really happened, and because the user thinks that if he wants
            to chat with the user that the symmetric key has been ACTUALLY sent to him,	he needs
            to ask for a symmetric key or send a new one again. It's better that we just erase that symmetric key.*/
            symKeys.erase(targetUuidStr);
        }
        delete resp;
        return -1;
    }
    else {
        size_t msgID;
        memcpy(&msgID, resp->payload + UUIDlength, sizeof(size_t));
        msgID = (size_t)ntohl(msgID);
        delete resp;
        delete[] mHdrBuff;
        return msgID;
    }
}
//Registers the client with the selected username received. Returns true if the user has been registered successfully or false if he wasn't.
bool client::registerClient(std::string& username) {
    char* publicKey = RSAkeys->second;
    char payload[publicKeyLength + MaxNameLenth];
    //Prepering the payload contents.
    memset(payload, '\0', MaxNameLenth + publicKeyLength);
    memcpy(payload, username.c_str(), username.length());
    char* pp = payload + MaxNameLenth;
    memcpy(pp, publicKey, publicKeyLength);
    respHdr* resp; //The payload contains the user's UUID.
    try {
        resp = createRespHdr(reqReg, publicKeyLength + MaxNameLenth, payload);
    }
    catch (const std::exception& e) {
        if (std::strstr(e.what(),std::to_string(respErr).c_str())!=NULL)
            std::cout << "The username you chose is already being used. Please register with a different username.\n"; //follows the protocol.
        else
            std::cout << e.what() << std::endl;
        return false;
    }
    if (resp->payload_size != UUIDlength) {
        throw customException("An error occured while trying to register to the server.");
    }
    //sets the new UUID and saving it at me.info
    memcpy(uid, resp->payload, UUIDlength); // sets the new UUID at client's uid attribute.
    const char* uidCP = UUIDbyteArrayToString((const unsigned char*)resp->payload);
    std::string uidST(uidCP);
    std::ofstream of("me.info");
    this->username = username;
    of << username << "\n";
    of << uidST << "\n";
    of << RSAkeys->first;
    of.close();
    std::cout << "connected as " << this->username << ".   UUID:" << uidST << std::endl;
    delete[] uidCP;
    delete resp;
    return true;
}
// Prints all the messages that has been sent to the user.
void client::pullMsgs() {
    respHdr* resp = createRespHdr(reqPullMsgs);// The payload contains a chain of message headers.
    if (resp->payload_size == 0) {
        std::cout << "There are no messages for you." << std::endl;
        return;
    }
    std::map<std::string, std::string>* m = getUsersMap();
    size_t i = 0;
    char* bp = resp->payload;
    char hdrBeforePayloadHolder[msgRespHdr_SizeBeforePL];
    while (i < resp->payload_size) {
        //processing each message
        memcpy(hdrBeforePayloadHolder, bp, msgRespHdr_SizeBeforePL);
        msgRespHdr hdr(hdrBeforePayloadHolder);
        bp += msgRespHdr_SizeBeforePL;
        i += msgRespHdr_SizeBeforePL;
        memcpy(hdr.content, bp, hdr.Message_Size);
        char* senderUuidCstr = (char*)UUIDbyteArrayToString((const unsigned char*)hdr.UUID);
        std::string senderUUID(senderUuidCstr);
        delete[] senderUuidCstr;
        std::cout << "Username: " << m->at(senderUUID) << "\n" << "Content:\n";
        switch (hdr.MessageType) {
        case msgTypeText: {
            //Decrypts the text message and print it.
            std::string contST(hdr.content, hdr.Message_Size);//contST is required for decrypt to work properly, especially the string's size.
            std::cout << customAES::decrypt(symKeys[senderUUID], contST) << std::endl;
            break;
        }
        case msgTypeSymReq: {
            std::cout << "Request for symmetric key" << std::endl;
            break;
        }
        case msgTypeSymSend: {
            //Decrypts the message, adds the received symmeteric key to the symKey map and notify the user.
            std::string contST(hdr.content, hdr.Message_Size); //contST is required for decrypt to work properly, especially the string's size.
            std::string symKeyHolder = customRSA::decrypt(contST, RSAkeys->first);
            char* symKey = new char[SymKeylenth];
            memcpy(symKey, symKeyHolder.c_str(), SymKeylenth);
            symKeys.insert(std::pair<std::string, char*>(senderUUID, symKey));
            std::cout << "Symmetric key received" << std::endl;
            break;
        }
        }
        //Proceed to the next message.
        bp += hdr.Message_Size;
        i += hdr.Message_Size;
    }
    delete m;
    delete resp;
}