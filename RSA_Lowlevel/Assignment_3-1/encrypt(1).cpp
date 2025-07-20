#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/modarith.h>  // For modular exponentiation
#include <cryptopp/secblock.h>   // For SecByteBlock
#include <cryptopp/hex.h>
#include <sstream>

using namespace CryptoPP;

// Maximum allowed size for n (adjusted based on key size, e.g., 2048-bit = 256 bytes)
const size_t MAX_N_SIZE = 256;

// Function to load the public key (n and e) from the binary file
void LoadPublicKey(const std::string& publicKeyFile, Integer& n, Integer& e) {
    std::ifstream pubFile(publicKeyFile, std::ios::binary);
    if (!pubFile.is_open()) {
        throw std::runtime_error("Could not open public key file.");
    }

    // Read n (modulus)
    size_t nSize;
    pubFile.read(reinterpret_cast<char*>(&nSize), sizeof(nSize));  // Read size of n

    // Ensure nSize is within a reasonable range
    if (nSize > MAX_N_SIZE) {
        throw std::runtime_error("nSize too large, potential file corruption.");
    }

    // Read n into a buffer and decode
    SecByteBlock nBuffer(nSize);
    pubFile.read(reinterpret_cast<char*>(nBuffer.data()), nSize);   // Read n itself
    n.Decode(nBuffer.data(), nSize);                                // Decode into Integer format

    // Read e (public exponent)
    size_t eSize;
    pubFile.read(reinterpret_cast<char*>(&eSize), sizeof(eSize));   // Read size of e

    // Ensure eSize is within a reasonable range
    if (eSize > MAX_N_SIZE) {
        throw std::runtime_error("eSize too large, potential file corruption.");
    }

    // Read e into a buffer and decode
    SecByteBlock eBuffer(eSize);
    pubFile.read(reinterpret_cast<char*>(eBuffer.data()), eSize);   // Read e itself
    e.Decode(eBuffer.data(), eSize);                                // Decode into Integer format

    pubFile.close();
}

// Function to convert the string message to an Integer
Integer StringToInteger(const std::string& message) {
    return Integer(reinterpret_cast<const byte*>(message.data()), message.size());
}

// Function to save the cipher to a binary file (with size information)
void SaveCipherToBinaryFile(const std::string& cipherOutputFile, const Integer& cipher) {
    std::ofstream cipherFile(cipherOutputFile, std::ios::binary);
    if (!cipherFile.is_open()) {
        throw std::runtime_error("Could not open cipher output file.");
    }

    // Get the byte size of the cipher
    size_t byteCount = cipher.MinEncodedSize();
    SecByteBlock buffer(byteCount);
    cipher.Encode(buffer.data(), byteCount);

    // Write the size of the cipher first
    cipherFile.write(reinterpret_cast<const char*>(&byteCount), sizeof(byteCount));

    // Write the actual cipher data
    cipherFile.write(reinterpret_cast<const char*>(buffer.data()), byteCount);
    cipherFile.close();
}


// Function to encrypt the message using m^e mod n
Integer EncryptMessage(const Integer& m, const Integer& e, const Integer& n) {
    return a_exp_b_mod_c(m, e, n);
}

// Function to read the message from a text file
std::string ReadFileToString(const std::string& dataFile) {
    std::ifstream file(dataFile);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open message file.");
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <public_key_file> <message_file> <cipher_output_file>" << std::endl;
        return 1;
    }

    std::string publicKeyFile = argv[1];
    std::string messageFile = argv[2];
    std::string cipherOutputFile = argv[3];

    try {
        // Load the public key (n and e)
        Integer n, e;
        LoadPublicKey(publicKeyFile, n, e);

        // Read the message from the message file
        std::string message = ReadFileToString(messageFile);

        // Convert the message to an Integer
        Integer m = StringToInteger(message);

        // Ensure the message integer is smaller than n
        if (m >= n) {
            throw std::runtime_error("Message is too large to encrypt with the given public key.");
        }

        // Encrypt the message
        Integer cipher = EncryptMessage(m, e, n);
        // std::cout<<"e: "<<e<<std::endl<<"n: "<<n<<std::endl<<"message: "<<message<<std::endl<<"m: "<<m<<std::endl<<"cipher: "<<cipher<<std::endl;
        // Save the cipher to a binary file
        SaveCipherToBinaryFile(cipherOutputFile, cipher);

        std::cout << "Message encrypted successfully!" << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
