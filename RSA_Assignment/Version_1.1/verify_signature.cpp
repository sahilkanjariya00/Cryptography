#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>

// Function to read the contents of a file into a vector
std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Function to load a public key from a PEM file
EVP_PKEY* loadPublicKey(const std::string& publicKeyFile) {
    FILE* fp = fopen(publicKeyFile.c_str(), "r");
    if (!fp) {
        std::cerr << "Error opening public key file: " << publicKeyFile << std::endl;
        return nullptr;
    }
    EVP_PKEY* pubKey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pubKey) {
        std::cerr << "Error reading public key from file: " << publicKeyFile << std::endl;
    }
    return pubKey;
}

int main() {
    // Load Alice's public key
    EVP_PKEY* pubKey = loadPublicKey("Alice's_public_key.pem");
    if (!pubKey) {
        return 1;
    }

    // Read the original message and the digital signature
    std::vector<unsigned char> originalMessage = readFile("decrypted_message.txt");
    std::vector<unsigned char> signature = readFile("decrypted_signature.bin");

    // Create and initialize the verification context
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        std::cerr << "Failed to create EVP_MD_CTX." << std::endl;
        EVP_PKEY_free(pubKey);
        return 1;
    }

    // Initialize the verification operation
    if (1 != EVP_DigestVerifyInit(mdCtx, nullptr, EVP_sha256(), nullptr, pubKey)) {
        std::cerr << "EVP_DigestVerifyInit failed." << std::endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pubKey);
        return 1;
    }

    // Feed the original message to the verification operation
    if (1 != EVP_DigestVerifyUpdate(mdCtx, originalMessage.data(), originalMessage.size())) {
        std::cerr << "EVP_DigestVerifyUpdate failed." << std::endl;
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pubKey);
        return 1;
    }

    // Verify the signature
    int result = EVP_DigestVerifyFinal(mdCtx, signature.data(), signature.size());
    if (result == 1) {
        std::cout << "Signature is valid." << std::endl;
    } else if (result == 0) {
        std::cout << "Signature is invalid." << std::endl;
    } else {
        std::cerr << "Error during signature verification." << std::endl;
    }

    // Cleanup
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pubKey);

    return 0;
}
