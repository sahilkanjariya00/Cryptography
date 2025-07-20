  #include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/sha.h>  // For SHA hash
#include <cryptopp/hex.h>  // For encoding the hash to hex (optional)
#include <iostream>
#include <fstream>
#include <ctime> //time

using namespace CryptoPP;

void Sign(const std::string& privKeyFile, const std::string& dataFile, const std::string& signatureFile) {
    // Read private key (d, n) from the binary file
    Integer d, n;
    FileSource privFile(privKeyFile.c_str(), true);
   // This line decodes the public exponent d from the file using the Basic Encoding Rules (BER) format
    d.BERDecode(privFile);
    //This line decodes the public exponent n from the file using the Basic Encoding Rules (BER) format
    n.BERDecode(privFile);

    // Read plaintext message from dataFile
    std::ifstream inFile(dataFile);
    std::string message;
    if (inFile.is_open()) {
        std::getline(inFile, message);  // Assuming message is a single line
    } else {
        std::cerr << "Error opening message file\n";
        return;
    }
    inFile.close();

    // Signing parth
    clock_t startTime, endTime; //time
    double elapsed_time; //time
    double avgTimeTaken, totalTimeTaken = 0.0; //time
    startTime = clock();

    // Hash the message using SHA-256
    byte hash[SHA256::DIGESTSIZE];//A byte array named hash is declared to 32Bytes constant
    //hash value has been calculated in HEXADECIMAL
    
    SHA256().CalculateDigest(hash, (const byte*)message.data(), message.size());
    //(const byte*)message.data(): The input data for hashing is obtained by converting the message (which is likely a std::string) to a const byte* pointer. This allows the CalculateDigest function to access the raw byte data of the string.

    // Convert the hash to Integer
    Integer h(hash, sizeof(hash));

    // Ensure the hash is smaller than the modulus n
    if (h >= n) {
        std::cerr << "Hash is too large. Must be smaller than modulus n.\n";
        return;
    }

    // Perform signing: signature = h(m)^d mod n
    Integer signature = a_exp_b_mod_c(h, d, n);
    endTime = clock();
    elapsed_time = static_cast<double>(endTime - startTime)/CLOCKS_PER_SEC*1000;
    totalTimeTaken = (totalTimeTaken + elapsed_time);
    // avgTimeTaken = (totalTimeTaken / n);
    std::cout << "Execution Cost = " << totalTimeTaken << " ms" << std::endl;
    
    // Write signature to binary file
    FileSink sigSink(signatureFile.c_str());
    signature.DEREncode(sigSink);
    sigSink.MessageEnd();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: ./sign <private_key_file> <data_file>\n";
        return 1;
    }

    Sign(argv[1], argv[2], "sign.bin");
    return 0;
}

