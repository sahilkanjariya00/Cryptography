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

using namespace CryptoPP;

// Load RSA private key from file (DER format)
RSA::PrivateKey LoadPrivateKey(const std::string& private_key_file) {
    RSA::PrivateKey privateKey;
    FileSource file(private_key_file.c_str(), true /*pumpAll*/);
    privateKey.BERDecode(file);
    return privateKey;
}

// Load binary data from file
std::string LoadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

// Save binary data to a file
void SaveToFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(data.data(), data.size());
}

// RSA decryption function for the session key
std::string RSADecryptSessionKey(const std::string& encrypted_session_key, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;
    std::string session_key;

    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    StringSource ss(encrypted_session_key, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(session_key)));

    return session_key;
}

// AES decryption function using CBC mode
std::string AESDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
    std::string decrypted;
    CBC_Mode<AES>::Decryption decryptor(reinterpret_cast<const byte*>(key.data()), key.size(), reinterpret_cast<const byte*>(iv.data()));
    StringSource ss(ciphertext, true, new StreamTransformationFilter(decryptor, new StringSink(decrypted)));
    return decrypted;
}

// Decrypt the data and extract the plaintext and signature
void decrypt_data(const std::string& encrypted_data_file, const std::string& encrypted_key_file, const std::string& private_key_file, const std::string& decrypted_data_file, const std::string& signature_file, size_t signature_size) {
    try {
        // Load Bob's RSA private key (in DER format)
        RSA::PrivateKey privateKey = LoadPrivateKey(private_key_file);

        // Load the encrypted session key and decrypt it
        std::string encrypted_session_key = LoadFile(encrypted_key_file);
        std::string session_key = RSADecryptSessionKey(encrypted_session_key, privateKey);

        // Load the encrypted data file (IV + ciphertext)
        std::string encrypted_data = LoadFile(encrypted_data_file);

        // Extract the IV from the first 16 bytes (for AES)
        std::string iv = encrypted_data.substr(0, AES::BLOCKSIZE);
        std::string ciphertext = encrypted_data.substr(AES::BLOCKSIZE);

        // Decrypt the concatenated data (signature + plaintext)
        std::string decrypted_data = AESDecrypt(ciphertext, session_key, iv);

        // Split the decrypted data into the signature and the plaintext
        std::string signature = decrypted_data.substr(0, signature_size);
        std::string plaintext = decrypted_data.substr(signature_size);

        // Save the plaintext and signature as separate files
        SaveToFile(decrypted_data_file, plaintext);
        SaveToFile(signature_file, signature);

        std::cout << "Decryption successful. Plaintext and signature extracted.\n";
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <encrypted data file> <encrypted key file> <private key file> <decrypted data file> <signature file>\n";
        return 1;
    }

    std::string encrypted_data_file = argv[1];
    std::string encrypted_key_file = argv[2];
    std::string private_key_file = argv[3];
    std::string decrypted_data_file = argv[4];
    std::string signature_file = argv[5];

    // Assuming the signature size is known (this needs to be predefined based on the signing key and algorithm)
    size_t signature_size = 256;  // For example, assuming a 2048-bit RSA signature (256 bytes)

    // Decrypt the data and extract the plaintext and signature
    decrypt_data(encrypted_data_file, encrypted_key_file, private_key_file, decrypted_data_file, signature_file, signature_size);

    return 0;
}

