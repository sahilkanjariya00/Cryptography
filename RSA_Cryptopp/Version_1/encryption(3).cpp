#include <iostream>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;

// Load RSA public key from file (DER format)
RSA::PublicKey LoadPublicKey(const std::string& public_key_file) {
    RSA::PublicKey publicKey;
    FileSource file(public_key_file.c_str(), true /*pumpAll*/);
    publicKey.BERDecode(file);
    return publicKey;
}

// Function to load the binary file into a string
std::string LoadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

// Function to save binary data to a file
void SaveToFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(data.data(), data.size());
}

// Function to generate a random AES-256 session key
std::string GenerateSessionKey() {
    AutoSeededRandomPool rng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);  // AES-256 = 32 bytes
    rng.GenerateBlock(key, key.size());
    return std::string(reinterpret_cast<const char*>(key.data()), key.size());
}

// AES encryption function using CBC mode
std::string AESEncrypt(const std::string& plaintext, const std::string& key, std::string& iv) {
    AutoSeededRandomPool rng;
    iv.resize(AES::BLOCKSIZE);  // IV size should be block size (16 bytes for AES)
    rng.GenerateBlock(reinterpret_cast<byte*>(&iv[0]), iv.size());

    std::string ciphertext;
    CBC_Mode<AES>::Encryption encryptor(reinterpret_cast<const byte*>(key.data()), key.size(), reinterpret_cast<const byte*>(iv.data()));
    StringSource ss(plaintext, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
    return ciphertext;
}

// RSA encryption function for the session key
std::string RSAEncryptSessionKey(const std::string& session_key, const RSA::PublicKey& publicKey) {
    AutoSeededRandomPool rng;
    std::string encryptedSessionKey;

    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    StringSource ss(session_key, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encryptedSessionKey)));

    return encryptedSessionKey;
}

// The main function to perform encryption
void encrypt_data(const std::string& signature_file, const std::string& data_file, const std::string& public_key_file, const std::string& encrypted_data_file, const std::string& encrypted_key_file) {
    try {
        // Load the signature and the data
        std::string signature = LoadFile(signature_file);
        std::string data = LoadFile(data_file);

        // Concatenate the signature with the data
        std::string concatenated_data = signature + data;

        // Generate a random AES-256 session key
        std::string session_key = GenerateSessionKey();

        // Encrypt the concatenated data using AES-256
        std::string iv;
        std::string encrypted_data = AESEncrypt(concatenated_data, session_key, iv);

        // Load Bob's RSA public key (in DER format)
        RSA::PublicKey publicKey = LoadPublicKey(public_key_file);

        // Encrypt the session key with Bob's RSA public key
        std::string encrypted_session_key = RSAEncryptSessionKey(session_key, publicKey);

        // Save the encrypted data and encrypted session key as binary files
        SaveToFile(encrypted_data_file, iv + encrypted_data);  // Prepend IV to the encrypted data
        SaveToFile(encrypted_key_file, encrypted_session_key);

        std::cout << "Data and session key encrypted successfully.\n";
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <signature file> <data file> <public key file> <encrypted data file> <encrypted key file>" << std::endl;
        return 1;
    }

    std::string signature_file = argv[1];
    std::string data_file = argv[2];
    std::string public_key_file = argv[3];
    std::string encrypted_data_file = argv[4];
    std::string encrypted_key_file = argv[5];

    // Encrypt the data and the session key
    encrypt_data(signature_file, data_file, public_key_file, encrypted_data_file, encrypted_key_file);

    return 0;
}

