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
public:
    static char* staticGenerate_key();
    static std::string createChiper(const char* symKey,std::string str);
    static std::string decrypt(const char* symKey, std::string str);
};

#endif;