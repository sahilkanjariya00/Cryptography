#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Function to read the contents of a file into a vector
std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return {};
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Function to write a vector to a file
void writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file for writing " << filename << std::endl;
        return;
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    // Read message and digital signature
    std::vector<unsigned char> message = readFile("message.txt");
    if (message.empty()) {
        std::cerr << "Error: Message file is empty or cannot be read." << std::endl;
        return 1;
    }

    std::vector<unsigned char> digitalSignature = readFile("digital_signature.bin");
    if (digitalSignature.empty()) {
        std::cerr << "Error: Digital signature file is empty or cannot be read." << std::endl;
        return 1;
    }

    // Concatenate message and digital signature
    message.insert(message.end(), digitalSignature.begin(), digitalSignature.end());

    // Generate a random session key for AES-256-CBC
    std::vector<unsigned char> sessionKey(32);  // AES-256 key size is 32 bytes
    if (!RAND_bytes(sessionKey.data(), sessionKey.size())) {
        std::cerr << "Error: Failed to generate random session key." << std::endl;
        return 1;
    }

    // Write the session key to a file
    writeFile("session_key.bin", sessionKey);

    // Initialize encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create encryption context." << std::endl;
        return 1;
    }

    // Generate random IV
    std::vector<unsigned char> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    if (!RAND_bytes(iv.data(), iv.size())) {
        std::cerr << "Error generating IV." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sessionKey.data(), iv.data())) {
        std::cerr << "Encryption initialization failed." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // Encrypt the data
    std::vector<unsigned char> encryptedMessage(message.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len, ciphertext_len;

    if (1 != EVP_EncryptUpdate(ctx, encryptedMessage.data(), &len, message.data(), message.size())) {
        std::cerr << "Encryption failed during update." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, encryptedMessage.data() + len, &len)) {
        std::cerr << "Encryption finalization failed." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len += len;

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    // Resize to actual ciphertext size
    encryptedMessage.resize(ciphertext_len);

    // Write the IV and the encrypted message to a file
    encryptedMessage.insert(encryptedMessage.begin(), iv.begin(), iv.end());
    writeFile("encrypted_message.bin", encryptedMessage);

    std::cout << "Encryption complete. Output written to encrypted_message.bin and session_key.bin" << std::endl;

    return 0;
}

