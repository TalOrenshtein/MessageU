/**
    @author Tal Orenshtein
*/


#include "client.h"

#define userReqReg 1
#define userReqList 2
#define userReqPubKey 3
#define userReqSendTextMsg 5
#define userReqSymKeyMsg 51
#define userReqSendSymKeyMsg 52
#define userReqPullMsgs 4
#define userExit 0

int main() {
    std::string menuUnReg= "1) Register\n2) Request for clients list\n3) Request for public key\n4) Request for waiting messages\n5) Send a text message\n51) Send a request for symmetric key\n52) Send your symmetric key\n0) Exit client\n? ";
    std::string menuReg= "2) Request for clients list\n3) Request for public key\n4) Request for waiting messages\n5) Send a text message\n51) Send a request for symmetric key\n52) Send your symmetric key\n0) Exit client\n? ";
    bool isReg = false;
    WSA wsa;
    client* c;
    std::cout << "MessageU client at your service." << std::endl;
    //infinite loop to handle the client's requests.
    bool exit = false;
    //check if client already registered.
    std::ifstream f("me.info");
    if (f.is_open() && !f.eof()) {
        std::string line;
        getline(f, line); //gets the username
        std::string username = line;
        getline(f, line); //gets the UUID
        uuid_t uuidFromFile;
        if (UuidFromStringA((RPC_CSTR)line.c_str(), &uuidFromFile) != RPC_S_OK) {
            std::cout << "Error occured while processing the UUID from \"me.info\" file." << std::endl;
            return 1;
        }
        f.close();
        char* uuid = (char*)UUIDtoByteArray(uuidFromFile);
        try {
            c = new client(customRSA::LoadAndGenPublicKey(), uuid, username);
            std::cout << "connected as " <<c->username<<".   UUID:"<<line<<std::endl; //note that the string line still holds the user's UUID.
        }
        catch (const std::exception& e) {
            if (std::string(e.what()) != "An error occured while connecting to the server.\n")
                std::cout << "The secret key that's found at \"me.info\" file is corrupted." << std::endl;
            return 1;
        }
        isReg = true;
    }
    else {
        c = new client();
    }
    while (true) {
        std::cout << "\nChoose the operation you want to do from that list:\n";
        isReg ? std::cout << menuReg : std::cout << menuUnReg;
        u_short req;
        std::string reqST;
        char* reqEndPt;
        do {
            std::cin >> reqST;
            req=std::strtol(reqST.c_str(), &reqEndPt, 10);
            if(*reqEndPt)
                std::cout << reqST << " is not a valid option. Please choose an operation from this list:" << std::endl;
        } while (*reqEndPt);  
        if (!isReg&& req != userReqReg && req != userExit) {
            std::cout << "You have to register before choosing other options." << std::endl;
            continue;
        }
        switch (req) {
        //The user wants to register. Makes sure that the user doesn't choose a name with special characters and that his username is within the character limit, and passes his request to further processing.
        case userReqReg: {
            if (isReg) {
                std::cout << "Option disabled: You are already registered."<< std::endl;
                continue;
            }
            std::cout << "Enter username: (There's 254 characters limit)\n? ";
            std::string username;
            client::chooseLegalUsername(username);
            try {
                isReg = c->registerClient(username);
            }
            catch (const std::exception& e) {
                std::cout << e.what() << std::endl;
                continue;
            }
            break;
        }
        //The user requests to receive a list of registered users. Gets the list and print it.
        case userReqList: {
            size_t i = 1;
            std::map<std::string, std::string>* m = c->getUsersMap();
            for (std::pair<std::string, std::string> e : *m) {
                if (i == 1)
                    std::cout << "Users list:" << std::endl;
                std::cout << i << ") " << e.second << std::endl;
                i += 1;
            }
            if (i == 1)
                std::cout << "You are the only one registered to the server." << std::endl;
            else
                std::cout << "End of list" << std::endl;
            delete m;
            break;
        }
        //The user requests the public key of user x. Passes the request to further processing. 
        case userReqPubKey: {
            std::cout << ("Enter the username of the user that you want his public key:\n? ");
            std::string username="";
            client::chooseLegalUsername(username);
            try {
                if (c->getPublicKey(username))
                    std::cout << "Public key received." << std::endl;
            }
            catch (const std::exception& e) {
                std::cout << e.what() << std::endl;
                continue;
            }
            break;
        }
        //The user requests to receive all the messages sent to him. Passes the request to further processing.
        case userReqPullMsgs: {
            try {
                c->pullMsgs();
            }
            catch (const std::exception& e) {
                std::cout << e.what() << std::endl;
                continue;
            }
            break;
        }
        //The user wants to send a text message. Passes the request to further processing, and prints the message ID or an error message.
        case userReqSendTextMsg: {
            long long msgID = c->sendMsg(msgTypeText); //msgId is long long type because I want to be able to store message ids up to 2^32-1, and be able to use negative numbers for errors.
            if (msgID> 0) {
                std::cout << "Message sent successfully. MessageID: " <<msgID<< std::endl;
            }
            else if (msgID == -1) {
                std::cout << "Oops. The message sent to someone else for some reason. Don't worry, it's encrypted ;)" << std::endl;
            }
            break;
        }
        //The user wants to request a symmetric key. Passes the request to further processing, and prints the message ID or an error message.
        case userReqSymKeyMsg: {
            long long msgID = c->sendMsg(msgTypeSymReq); //msgId is long long type because I want to be able to store message ids up to 2^32-1, and be able to use negative numbers for errors.
            if (msgID>0) {
                std::cout << "A request for symmetric key has been sent. MessageID: " << msgID << std::endl;
            }
            else if(msgID==-1){
                std::cout << "There was a failiure during sending the request for symmetric key. Please try again."<< std::endl;
            }
            break;
        }
        //The user wants to send his symmetric key. Passes the request to further processing, and prints the message ID or an error message.
        case userReqSendSymKeyMsg: {
            long long msgID = c->sendMsg(msgTypeSymSend); //msgId is long long type because I want to be able to store message ids up to 2^32-1, and be able to use negative numbers for errors.
            if(msgID>0)
                std::cout << "The symmetric key has been sent. MessageID: "<<msgID<< std::endl;
            else if (msgID == -1) {
                std::cout << "There was a failiure during sending the symmetric key. Please try again." << std::endl;
            }
            break;
        }
        //The user requests to exit the program. Marks that the user wants to exit.
        case userExit: {
            exit = true;
            break;
        }
        //The user entered an unvalid input.
        default: {
            std::cout << req << " is not a valid option. Please choose an option from this list:" << std::endl;
            break;
        }
        }
        // If the user requested to exit the program, free all resources and exit the program.
        if (exit) {
            delete c;
            break;
        }
    }
    return 0;
}
