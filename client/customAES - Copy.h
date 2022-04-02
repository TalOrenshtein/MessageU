#ifndef AES_H
#define AES_H

#include <modes.h>
#include <aes.h>
#include <filters.h>

#include <iostream>
#include <string>
#include <immintrin.h>	// _rdrand32_step

#define SymKeylenth CryptoPP::AES::DEFAULT_KEYLENGTH

class customAES {
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];

    char* generate_key(char* buff, size_t size);
public:
    customAES();
    customAES(const char* symKey);
    static char* staticGenerate_key();
    static std::string createChiper(const char* symKey,std::string str);
    static std::string decrypt(const char* symKey, std::string str);
    const char* getKey();
};

#endif;