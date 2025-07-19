// decrypt_data.cpp
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <iostream>
#include <fstream>
#include <vector>

// Helper function to read private key from PEM file
EVP_PKEY* load_private_key(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        std::cerr << "Error opening private key file: " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey) {
        std::cerr << "Error reading private key from file: " << filename << std::endl;
    }

    return pkey;
}

// Helper function to read a file into a vector
std::vector<unsigned char> read_file(const char* filename) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return {};
    }

    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return buffer;
}

// Helper function to write a vector to a file
bool write_file(const char* filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::out | std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for writing: " << filename << std::endl;
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    return true;
}

// Function to decrypt the session key using RSA private key
std::vector<unsigned char> decrypt_session_key(EVP_PKEY* privkey, const std::vector<unsigned char>& encrypted_session_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, nullptr);
    if (!ctx) {
        std::cerr << "Error creating context for private key decryption." << std::endl;
        return {};
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::cerr << "Error initializing private key decryption." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    size_t decrypted_key_len = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &decrypted_key_len, encrypted_session_key.data(), encrypted_session_key.size()) <= 0) {
        std::cerr << "Error determining buffer size for decrypted key." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> decrypted_key(decrypted_key_len);
    if (EVP_PKEY_decrypt(ctx, decrypted_key.data(), &decrypted_key_len, encrypted_session_key.data(), encrypted_session_key.size()) <= 0) {
        std::cerr << "Error decrypting session key." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    return decrypted_key;
}

// Function to decrypt data using AES
std::vector<unsigned char> decrypt_aes(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context." << std::endl;
        return {};
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        std::cerr << "Error initializing AES decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        std::cerr << "Error during AES decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "Error finalizing AES decryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

int main() {
    const char* encrypted_data_file = "encrypted_data.bin";
    const char* encrypted_session_key_file = "encrypted_session_key.bin";
    const char* private_key_file = "Bob's_private_key.pem";
    const char* decrypted_message_file = "decrypted_message.txt";
    const char* decrypted_signature_file = "decrypted_digital_signature.bin";

    // Load receiver's private key (Bob's private key)
    EVP_PKEY* privkey = load_private_key(private_key_file);
    if (!privkey) {
        return 1;
    }

    // Read encrypted session key and data from files
    std::vector<unsigned char> encrypted_session_key = read_file(encrypted_session_key_file);
    std::vector<unsigned char> encrypted_data = read_file(encrypted_data_file);
    if (encrypted_session_key.empty() || encrypted_data.empty()) {
        EVP_PKEY_free(privkey);
        return 1;
    }

    // Decrypt the session key using the receiver's private key
    std::vector<unsigned char> session_key = decrypt_session_key(privkey, encrypted_session_key);
    if (session_key.empty()) {
        EVP_PKEY_free(privkey);
        return 1;
    }

    // Decrypt the concatenated data using the decrypted session key
    std::vector<unsigned char> iv(AES_BLOCK_SIZE, 0); // The same IV used in encryption must be used here
    std::vector<unsigned char> decrypted_data = decrypt_aes(encrypted_data, session_key, iv);
    if (decrypted_data.empty()) {
        EVP_PKEY_free(privkey);
        return 1;
    }

    // Determine the split point between the message and the signature
    size_t signature_length = SHA256_DIGEST_LENGTH; // Assuming SHA-256 hash length for signature
    size_t message_length = decrypted_data.size() - signature_length;

    // Extract the message and the signature from the decrypted data
    std::vector<unsigned char> decrypted_message(decrypted_data.begin(), decrypted_data.begin() + message_length);
    std::vector<unsigned char> decrypted_signature(decrypted_data.begin() + message_length, decrypted_data.end());

    // Save the decrypted message and signature to files
    if (!write_file(decrypted_message_file, decrypted_message)) {
        std::cerr << "Error writing decrypted message to file." << std::endl;
        EVP_PKEY_free(privkey);
        return 1;
    }

    if (!write_file(decrypted_signature_file, decrypted_signature)) {
        std::cerr << "Error writing decrypted digital signature to file." << std::endl;
        EVP_PKEY_free(privkey);
        return 1;
    }

    std::cout << "Decryption successful. Decrypted files saved." << std::endl;

    EVP_PKEY_free(privkey);
    return 0;
}

