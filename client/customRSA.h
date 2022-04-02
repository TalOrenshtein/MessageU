#ifndef CUSTOMRSA_H
#define CUSTOMRSA_H

#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <hex.h>
#include <fstream>
#include <string>
#include <iostream>


#define UUIDlength 16
#define publicKeyLength 160
#define cipherTextLength 128

class customRSA {
public:
    static std::pair<std::string, char*>* GenKeyPair();
    static std::pair<std::string, char*>* LoadAndGenPublicKey();
    static std::string encrypt(char* publicKey, char* message);
    static std::string decrypt(std::string ciphertext, std::string privKey);
};

#endif;