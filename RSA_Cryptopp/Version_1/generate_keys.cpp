#include <iostream>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

// Function to generate RSA public and private keys and store them in separate binary files
void generate_keys(const std::string& public_key_file, const std::string& private_key_file) {
    try {
        // Generate RSA keys
        AutoSeededRandomPool rng;
        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 2048);  // RSA 2048-bit key

        // Create RSA keys
        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters);

        // Save public key
        FileSink publicFile(public_key_file.c_str());
        publicKey.DEREncode(publicFile);  // Save public key in DER format
        publicFile.MessageEnd();

        // Save private key
        FileSink privateFile(private_key_file.c_str());
        privateKey.DEREncode(privateFile);  // Save private key in DER format
        privateFile.MessageEnd();

        std::cout << "RSA keys generated and saved successfully.\n";
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <public key file> <private key file>" << std::endl;
        return 1;
    }

    std::string public_key_file = argv[1];
    std::string private_key_file = argv[2];

    // Call the generate_keys function
    generate_keys(public_key_file, private_key_file);

    return 0;
}

