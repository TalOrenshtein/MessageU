#include "customRSA.h"

//Generates new pair of keys.
std::pair<std::string, char*>* customRSA::GenKeyPair() {
	std::pair<std::string, char*>* keys = new std::pair<std::string, char*>;
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024);
	CryptoPP::Base64Encoder privkeysink(new CryptoPP::StringSink(keys->first));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();
	CryptoPP::RSAFunction pubkey(privkey);
	std::string pubKeyST;
	CryptoPP::Base64Encoder pubkeysink(new CryptoPP::StringSink(pubKeyST));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();
	CryptoPP::byte buf[publicKeyLength];
	CryptoPP::ArraySink as(buf, publicKeyLength);
	pubkey.Save(as);
	char* pubKey = new char[publicKeyLength];
	memcpy(pubKey, buf, publicKeyLength);
	keys->second = pubKey;
	return keys;
}
// Loads the private key from me.info and generates the public key.
std::pair<std::string, char*>* customRSA::LoadAndGenPublicKey() {
	std::pair<std::string, char*>* keys = new std::pair<std::string, char*>;
	CryptoPP::ByteQueue bytes;
	std::string ss;
	std::string privKey;
	std::ifstream ost("me.info");
	getline(ost, ss);// skips username
	getline(ost, ss);// skips UUID
	CryptoPP::FileSource file(ost, true, new CryptoPP::Base64Decoder);
	file.TransferTo(bytes);
	bytes.MessageEnd();
	CryptoPP::RSA::PrivateKey privateKey;
	privateKey.Load(bytes);
	CryptoPP::Base64Encoder privkeysink(new CryptoPP::StringSink(privKey));
	privateKey.DEREncode(privkeysink);
	privkeysink.MessageEnd();
	CryptoPP::RSAFunction pubkey(privateKey);
	CryptoPP::byte buf[publicKeyLength];
	CryptoPP::ArraySink as(buf, publicKeyLength);
	pubkey.Save(as);
	char* pubKey = new char[publicKeyLength];
	memcpy(pubKey, buf, publicKeyLength);
	keys->first = privKey;
	keys->second = pubKey;
	return keys;
}
// encrypts a message using a public key.
std::string customRSA::encrypt(char* publicKey, char* message) {
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::byte buf[publicKeyLength];
	memcpy(buf, publicKey, publicKeyLength);
	CryptoPP::ArraySource as(buf, publicKeyLength, true);
	CryptoPP::RSA::PublicKey pubKey;
	pubKey.Load(as);
	std::string ciphertext;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(pubKey);
	CryptoPP::StringSource ss(message, true, new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(ciphertext)));
	return ciphertext;
}
//decrypts a message using a private key.
std::string customRSA::decrypt(std::string ciphertext,std::string privKey) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ByteQueue bytes;
    CryptoPP::StringSource sts(privKey, true, new CryptoPP::Base64Decoder);
    sts.TransferTo(bytes);
    bytes.MessageEnd();
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.Load(bytes);
    std::string decrypted;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);
    CryptoPP::StringSource ss(ciphertext, true, new CryptoPP::PK_DecryptorFilter(rng, d, new CryptoPP::StringSink(decrypted)));
    return decrypted;
}