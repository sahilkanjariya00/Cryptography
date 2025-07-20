// encrypt_message.cpp
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <iostream>
#include <fstream>
#include <vector>

// Helper function to read public key from PEM file
EVP_PKEY* load_public_key(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        std::cerr << "Error opening public key file: " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey) {
        std::cerr << "Error reading public key from file: " << filename << std::endl;
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

// Function to generate a random session key
std::vector<unsigned char> generate_session_key(int key_size) {
    std::vector<unsigned char> key(key_size);
    if (!RAND_bytes(key.data(), key.size())) {
        std::cerr << "Error generating random session key." << std::endl;
        return {};
    }
    return key;
}

// Function to encrypt data using AES
std::vector<unsigned char> encrypt_aes(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context." << std::endl;
        return {};
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0;
    int ciphertext_len = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        std::cerr << "Error initializing AES encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        std::cerr << "Error during AES encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cerr << "Error finalizing AES encryption." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Function to encrypt the session key using RSA public key
std::vector<unsigned char> encrypt_session_key(EVP_PKEY* pubkey, const std::vector<unsigned char>& session_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
    if (!ctx) {
        std::cerr << "Error creating context for public key encryption." << std::endl;
        return {};
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "Error initializing public key encryption." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    size_t encrypted_key_len = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &encrypted_key_len, session_key.data(), session_key.size()) <= 0) {
        std::cerr << "Error determining buffer size for encrypted key." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> encrypted_key(encrypted_key_len);
    if (EVP_PKEY_encrypt(ctx, encrypted_key.data(), &encrypted_key_len, session_key.data(), session_key.size()) <= 0) {
        std::cerr << "Error encrypting session key." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    return encrypted_key;
}

int main() {
    const char* message_file = "message.txt";
    const char* signature_file = "digital_signature.bin";
    const char* public_key_file = "Bob's_public_key.pem";
    const char* encrypted_data_file = "encrypted_data.bin";
    const char* encrypted_session_key_file = "encrypted_session_key.bin";
    const char* session_key_file = "session_key.bin";

    // Load receiver's public key (Bob's public key)
    EVP_PKEY* pubkey = load_public_key(public_key_file);
    if (!pubkey) {
        return 1;
    }

    // Read message and digital signature from files
    std::vector<unsigned char> message_data = read_file(message_file);
    std::vector<unsigned char> signature_data = read_file(signature_file);
    if (message_data.empty() || signature_data.empty()) {
        EVP_PKEY_free(pubkey);
        return 1;
    }

    // Generate a random session key
    std::vector<unsigned char> session_key = generate_session_key(32); // AES-256 requires a 32-byte key
    if (session_key.empty()) {
        EVP_PKEY_free(pubkey);
        return 1;
    }

    // Write the session key to a file (for demonstration purposes; this should be handled securely in real applications)
    if (!write_file(session_key_file, session_key)) {
        std::cerr << "Error writing session key to file." << std::endl;
        EVP_PKEY_free(pubkey);
        return 1;
    }

    // Concatenate the message and signature data
    std::vector<unsigned char> combined_data(message_data);
    combined_data.insert(combined_data.end(), signature_data.begin(), signature_data.end());

    // Encrypt the concatenated data (message + signature) with the session key using AES
    std::vector<unsigned char> iv(AES_BLOCK_SIZE); // Initialize IV with zeros or use a secure IV
    if (!RAND_bytes(iv.data(), iv.size())) {
        std::cerr << "Error generating IV." << std::endl;
        EVP_PKEY_free(pubkey);
        return 1;
    }

    std::vector<unsigned char> encrypted_data = encrypt_aes(combined_data, session_key, iv);
    if (encrypted_data.empty()) {
        EVP_PKEY_free(pubkey);
        return 1;
    }

    // Save the encrypted data to a file
    if (!write_file(encrypted_data_file, encrypted_data)) {
        std::cerr << "Error writing encrypted data to file." << std::endl;
        EVP_PKEY_free(pubkey);
        return 1;
    }

    // Encrypt the session key using the receiver's public key
    std::vector<unsigned char> encrypted_session_key = encrypt_session_key(pubkey, session_key);
    if (encrypted_session_key.empty()) {
        EVP_PKEY_free(pubkey);
        return 1;
    }

    // Save the encrypted session key to a file
    if (!write_file(encrypted_session_key_file, encrypted_session_key)) {
        std::cerr << "Error writing encrypted session key to file." << std::endl;
        EVP_PKEY_free(pubkey);
        return 1;
    }

    std::cout << "Encryption successful. Encrypted data and keys saved." << std::endl;

    EVP_PKEY_free(pubkey);
    return 0;
}

