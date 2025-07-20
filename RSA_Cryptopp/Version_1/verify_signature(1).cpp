#include <iostream>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

// Load RSA public key from file (DER format)
RSA::PublicKey LoadPublicKey(const std::string& public_key_file) {
    RSA::PublicKey publicKey;
    FileSource file(public_key_file.c_str(), true /*pumpAll*/);
    publicKey.BERDecode(file);
    return publicKey;
}

// Load binary data from file
std::string LoadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

// Verify the digital signature
bool VerifySignature(const std::string& public_key_file, const std::string& data_file, const std::string& signature_file) {
    try {
        // Load Alice's RSA public key (in DER format)
        RSA::PublicKey publicKey = LoadPublicKey(public_key_file);

        // Load the decrypted data and the signature
        std::string data = LoadFile(data_file);
        std::string signature = LoadFile(signature_file);

        // Create a PSS verifier object (RSA with PSS padding and SHA-256)
        RSASS<PSS, SHA256>::Verifier verifier(publicKey);

        // Perform signature verification
        bool result = false;
        StringSource ss(data + signature, true, // First pass the data, then the signature for verification
            new SignatureVerificationFilter(verifier, nullptr,
                SignatureVerificationFilter::THROW_EXCEPTION | SignatureVerificationFilter::PUT_MESSAGE));

        std::cout << "Signature verification successful! The data is authentic.\n";
        return true;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Signature verification failed! Error: " << e.what() << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <public key file> <data file> <signature file>\n";
        return 1;
    }

    std::string public_key_file = argv[1];
    std::string data_file = argv[2];
    std::string signature_file = argv[3];

    // Verify the digital signature
    bool valid = VerifySignature(public_key_file, data_file, signature_file);

    if (valid) {
        std::cout << "Signature verification passed.\n";
    } else {
        std::cout << "Signature verification failed.\n";
    }

    return 0;
}

