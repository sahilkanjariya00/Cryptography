// sign_message.cpp
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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

// Function to read a file into a vector
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

// Function to write a vector to a file
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

// Function to generate a digital signature using a private key
std::vector<unsigned char> sign_data(EVP_PKEY* privkey, const std::vector<unsigned char>& data) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        std::cerr << "Error creating message digest context." << std::endl;
        return {};
    }

    if (1 != EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, privkey)) {
        std::cerr << "Error initializing DigestSign." << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    if (1 != EVP_DigestSignUpdate(md_ctx, data.data(), data.size())) {
        std::cerr << "Error updating DigestSign." << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    size_t sig_len = 0;
    if (1 != EVP_DigestSignFinal(md_ctx, nullptr, &sig_len)) {
        std::cerr << "Error obtaining signature length." << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    std::vector<unsigned char> signature(sig_len);
    if (1 != EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len)) {
        std::cerr << "Error creating signature." << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return {};
    }

    signature.resize(sig_len);
    EVP_MD_CTX_free(md_ctx);
    return signature;
}

int main() {
    const char* message_file = "message.txt";
    const char* private_key_file = "Alice's_private_key.pem";
    const char* signature_file = "digital_signature.bin";

    // Load sender's private key (Alice's private key)
    EVP_PKEY* privkey = load_private_key(private_key_file);
    if (!privkey) {
        return 1;
    }

    // Read message data from file
    std::vector<unsigned char> message_data = read_file(message_file);
    if (message_data.empty()) {
        EVP_PKEY_free(privkey);
        return 1;
    }

    // Sign the message data
    std::vector<unsigned char> signature = sign_data(privkey, message_data);
    if (signature.empty()) {
        EVP_PKEY_free(privkey);
        return 1;
    }

    // Save the signature to a file
    if (!write_file(signature_file, signature)) {
        std::cerr << "Error writing signature to file." << std::endl;
        EVP_PKEY_free(privkey);
        return 1;
    }

    std::cout << "Digital signature created and saved to " << signature_file << std::endl;

    EVP_PKEY_free(privkey);
    return 0;
}

