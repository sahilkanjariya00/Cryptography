#include <iostream>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

// Function to load RSA private key from file (DER format)
RSA::PrivateKey LoadPrivateKey(const std::string& private_key_file) {
    RSA::PrivateKey privateKey;
    FileSource file(private_key_file.c_str(), true /*pumpAll*/);
    privateKey.BERDecode(file);
    return privateKey;
}

// Function to create a digital signature
void create_signature(const std::string& private_key_file, const std::string& data_file, const std::string& signature_file) {
    try {
        // Load the sender's private key
        RSA::PrivateKey privateKey = LoadPrivateKey(private_key_file);

        // Read the data from the file
        std::string data;
        FileSource(data_file.c_str(), true, new StringSink(data));

        // Create a random number generator
        AutoSeededRandomPool rng;

        // Create a PSS signer object (RSA with PSS padding and SHA-256)
        RSASS<PSS, SHA256>::Signer signer(privateKey);

        // Generate the signature
        std::string signature;
        StringSource(data, true, 
            new SignerFilter(rng, signer, new StringSink(signature)));

        // Save the signature in binary format
        FileSink signatureFile(signature_file.c_str());
        signatureFile.Put((const byte*)signature.data(), signature.size());
        signatureFile.MessageEnd();

        std::cout << "Digital signature created and saved in binary format successfully.\n";
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <private key file> <data file> <signature file>" << std::endl;
        return 1;
    }

    std::string private_key_file = argv[1];
    std::string data_file = argv[2];
    std::string signature_file = argv[3];

    // Create the digital signature
    create_signature(private_key_file, data_file, signature_file);

    return 0;
}

