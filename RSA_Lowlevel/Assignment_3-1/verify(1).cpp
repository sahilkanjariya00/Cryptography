#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/modarith.h>
#include <cryptopp/sha.h>    // For SHA-256
#include <cryptopp/secblock.h>
#include <sstream>           // For stringstream

using namespace CryptoPP;

// Maximum allowed size for n (adjusted based on key size, e.g., 2048-bit = 256 bytes)
const size_t MAX_N_SIZE = 256;

// Function to load the public key (n and e) from the binary file
void LoadPublicKey(const std::string& publicKeyFile, Integer& n, Integer& e) {
    std::ifstream pubFile(publicKeyFile, std::ios::binary);
    if (!pubFile.is_open()) {
        throw std::runtime_error("Could not open public key file.");
    }

    // Read 'n' (modulus)
    size_t nSize;
    pubFile.read(reinterpret_cast<char*>(&nSize), sizeof(nSize));
    if (nSize > MAX_N_SIZE) {
        throw std::runtime_error("Error: n size exceeds the maximum allowed size.");
    }

    SecByteBlock nBuffer(nSize);
    pubFile.read(reinterpret_cast<char*>(nBuffer.data()), nSize);
    n.Decode(nBuffer.data(), nSize);

    // Read 'e' (public exponent)
    size_t eSize;
    pubFile.read(reinterpret_cast<char*>(&eSize), sizeof(eSize));
    if (eSize > MAX_N_SIZE) {
        throw std::runtime_error("Error: e size exceeds the maximum allowed size.");
    }

    SecByteBlock eBuffer(eSize);
    pubFile.read(reinterpret_cast<char*>(eBuffer.data()), eSize);
    e.Decode(eBuffer.data(), eSize);

    pubFile.close();
}

// Function to generate SHA-256 hash of the input data
Integer GenerateDigest(const std::string& message) {
    SHA256 hash;
    SecByteBlock digest(hash.DigestSize());

    // Calculate the hash (digest)
    hash.Update(reinterpret_cast<const byte*>(message.data()), message.size());
    hash.Final(digest);

    // Convert digest into Integer format
    return Integer(digest, digest.size());
}

// Function to read the signature from a binary file
Integer ReadSignatureFromFile(const std::string& signatureFile) {
    std::ifstream sigFile(signatureFile, std::ios::binary);
    if (!sigFile.is_open()) {
        throw std::runtime_error("Could not open signature file.");
    }

    size_t sigSize;
    sigFile.read(reinterpret_cast<char*>(&sigSize), sizeof(sigSize));
    if (sigSize > MAX_N_SIZE) {
        throw std::runtime_error("Error: Signature size exceeds the maximum allowed size.");
    }

    SecByteBlock sigBuffer(sigSize);
    sigFile.read(reinterpret_cast<char*>(sigBuffer.data()), sigSize);
    Integer signature;
    signature.Decode(sigBuffer.data(), sigSize);

    sigFile.close();
    return signature;
}

// Function to decrypt the signature using the public key (signature^e mod n)
Integer DecryptSignature(const Integer& signature, const Integer& e, const Integer& n) {
    return a_exp_b_mod_c(signature, e, n);  // Decrypt: signature^e mod n
}

// Function to read the message from a file
std::string ReadFileToString(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open message file.");
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <public_key_file> <message_file> <signature_file>" << std::endl;
        return 1;
    }

    std::string publicKeyFile = argv[1];
    std::string messageFile = argv[2];
    std::string signatureFile = argv[3];

    try {
        // Load the public key (n and e)
        Integer n, e;
        LoadPublicKey(publicKeyFile, n, e);

        // Read the message from the file
        std::string message = ReadFileToString(messageFile);

        // Generate the hash (digest) of the message
        Integer digest = GenerateDigest(message);

        // Read the signature from the file
        Integer signature = ReadSignatureFromFile(signatureFile);

        // Decrypt the signature using the public key
        Integer decryptedDigest = DecryptSignature(signature, e, n);

        // std::cout<<"n: "<<n<<std::endl<<"e: "<<e<<std::endl<<"dData: "<<message<<std::endl<<"generated digest:"<<digest<<std::endl<<"Decrypted digest: "<<decryptedDigest;
        // Compare the decrypted digest with the generated digest
        if (decryptedDigest == digest) {
            std::cout << "Signature is valid. The message has not been tampered with." << std::endl;
        } else {
            std::cout << "Signature is invalid. The message may have been altered." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
