#include "customAES.h"
//Genetares a key and returns a pointer to it.
char* customAES::staticGenerate_key() {
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    char* buff = new char[CryptoPP::AES::DEFAULT_KEYLENGTH];
    memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
    for (size_t i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i += 4)
        _rdrand32_step(reinterpret_cast<unsigned int*>(&key[i]));
    memcpy(buff, reinterpret_cast<char*>(key), CryptoPP::AES::DEFAULT_KEYLENGTH);
    return buff;
}
//Creates a chipper using a symmatric key.
std::string customAES::createChiper(const char* symKey, std::string str) {
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
    memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);
    memcpy(reinterpret_cast<char*>(key), symKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::string cipherText;
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(str.c_str()), str.length());
    stfEncryptor.MessageEnd();
    return cipherText;
}
//Decrypts using a symmetric key.
std::string customAES::decrypt(const char* symKey, std::string str) {
    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
    memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);
    memcpy(reinterpret_cast<char*>(key), symKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::string decryptedText;
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedText));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(str.c_str()), str.size());
    stfDecryptor.MessageEnd();
    return decryptedText;
}