#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Function to read the contents of a file into a vector
std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Function to write a vector to a file
void writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    // Read the encrypted message
    std::vector<unsigned char> encryptedData = readFile("encrypted_message.bin");

    // Read session key
    std::vector<unsigned char> sessionKey = readFile("session_key.bin");

    // Extract the IV from the encrypted data
    std::vector<unsigned char> iv(encryptedData.begin(), encryptedData.begin() + EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<unsigned char> encryptedMessage(encryptedData.begin() + iv.size(), encryptedData.end());

    // Initialize decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create decryption context." << std::endl;
        return 1;
    }

    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sessionKey.data(), iv.data())) {
        std::cerr << "Decryption initialization failed." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // Decrypt the data
    std::vector<unsigned char> decryptedMessage(encryptedMessage.size());
    int len, plaintext_len;

    if (1 != EVP_DecryptUpdate(ctx, decryptedMessage.data(), &len, encryptedMessage.data(), encryptedMessage.size())) {
        std::cerr << "Decryption failed." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    plaintext_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedMessage.data() + len, &len)) {
        std::cerr << "Decryption finalization failed." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    plaintext_len += len;

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    // Resize to actual plaintext size
    decryptedMessage.resize(plaintext_len);

    // Assuming you know the size of the original message
    size_t messageSize = 21;  // Adjust this size based on the actual size of message.txt
    std::vector<unsigned char> originalMessage(decryptedMessage.begin(), decryptedMessage.begin() + messageSize);
    std::vector<unsigned char> digitalSignature(decryptedMessage.begin() + messageSize, decryptedMessage.end());

    // Write the original message and digital signature to separate files
    writeFile("decrypted_message.txt", originalMessage);
    writeFile("decrypted_signature.bin", digitalSignature);

    std::cout << "Decryption complete. Output written to decrypted_message.txt and decrypted_signature.bin" << std::endl;

    return 0;
}
