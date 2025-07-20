#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <fstream>
#include <ctime> //time

using namespace CryptoPP;

// Function to calculate the SHA-256 hash of a message
Integer CalculateHash(const std::string& message) {
    // Create a SHA-256 hash object
    SHA256 hash;

    // Prepare a byte array to hold the hash output
    byte digest[SHA256::DIGESTSIZE];

    // Calculate the hash
    hash.CalculateDigest(digest, (const byte*)message.data(), message.size());

    // Return the hash as an Integer
    return Integer(digest, sizeof(digest));
}

void Verify(const std::string& pubKeyFile, const std::string& dataFile, const std::string& signatureFile) {
    // Read public key (e, n) from the binary file
    Integer e, n;
    FileSource pubFile(pubKeyFile.c_str(), true);
    e.BERDecode(pubFile);
    n.BERDecode(pubFile);

    // Read the original message from dataFile
    std::ifstream inFile(dataFile);
    std::string message;
    if (inFile.is_open()) {
        std::getline(inFile, message);  // Assuming message is a single line
    } else {
        std::cerr << "Error opening message file\n";
        return;
    }
    inFile.close();

    // Read the signature from the signatureFile
    Integer signature;
    FileSource sigFile(signatureFile.c_str(), true);
    signature.BERDecode(sigFile);

    //Calculate time
    clock_t startTime, endTime; //time
    double elapsed_time; //time
    double avgTimeTaken, totalTimeTaken = 0.0; //time
    startTime = clock();

    // Calculate the hash of the original message
    Integer h = CalculateHash(message);

    // Verify signature: h' = signature^e mod n
    Integer h_prime = a_exp_b_mod_c(signature, e, n);

    // Check if h' == h
    if (h_prime == h) {
        std::cout << "Success: The signature is valid.\n";
    } else {
        std::cout << "Failure: The signature is invalid.\n";
    }

    endTime = clock();
    elapsed_time = static_cast<double>(endTime - startTime)/CLOCKS_PER_SEC*1000;
    totalTimeTaken = (totalTimeTaken + elapsed_time);
    // avgTimeTaken = (totalTimeTaken / n);
    std::cout << "\nExecution Cost = " << totalTimeTaken << " ms" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: ./verify <public_key_file> <data_file> <signature_file>\n";
        return 1;
    }

    Verify(argv[1], argv[2], argv[3]);
    return 0;
}

