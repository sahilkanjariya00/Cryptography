#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/modarith.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>    // For SHA-256
#include <cryptopp/hex.h>    // For hex encoding
#include <sstream>

using namespace CryptoPP;

// Maximum allowed size for n (adjusted based on key size, e.g., 2048-bit = 256 bytes)
const size_t MAX_N_SIZE = 256;

// Function to load the private key (n and d) from the binary file
void LoadPrivateKey(const std::string& privateKeyFile, Integer& n, Integer& d) {
    std::ifstream privFile(privateKeyFile, std::ios::binary);
    if (!privFile.is_open()) {
        throw std::runtime_error("Could not open private key file.");
    }

    // Read 'n' (modulus) from the private key file
    size_t nSize;
    privFile.read(reinterpret_cast<char*>(&nSize), sizeof(nSize));
    if (nSize > MAX_N_SIZE) {
        throw std::runtime_error("Error: n size exceeds the maximum allowed size.");
    }

    SecByteBlock nBuffer(nSize);
    privFile.read(reinterpret_cast<char*>(nBuffer.data()), nSize);
    n.Decode(nBuffer.data(), nSize);

    // Read 'd' (private exponent) from the private key file
    size_t dSize;
    privFile.read(reinterpret_cast<char*>(&dSize), sizeof(dSize));
    if (dSize > MAX_N_SIZE) {
        throw std::runtime_error("Error: d size exceeds the maximum allowed size.");
    }

    SecByteBlock dBuffer(dSize);
    privFile.read(reinterpret_cast<char*>(dBuffer.data()), dSize);
    d.Decode(dBuffer.data(), dSize);

    privFile.close();
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

// Function to sign the digest using the private key (digest^d mod n)
Integer SignDigest(const Integer& digest, const Integer& d, const Integer& n) {
    return a_exp_b_mod_c(digest, d, n);  // RSA signing: digest^d mod n
}

// Function to save the signature to a binary file
void SaveSignatureToFile(const std::string& signatureFile, const Integer& signature) {
    std::ofstream sigFile(signatureFile, std::ios::binary);
    if (!sigFile.is_open()) {
        throw std::runtime_error("Could not open signature file.");
    }

    // Save the signature size and the signature itself
    size_t sigSize = signature.MinEncodedSize();
    SecByteBlock buffer(sigSize);
    signature.Encode(buffer.data(), sigSize);

    sigFile.write(reinterpret_cast<const char*>(&sigSize), sizeof(sigSize));  // Write size
    sigFile.write(reinterpret_cast<const char*>(buffer.data()), sigSize);     // Write signature
    sigFile.close();
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
        std::cerr << "Usage: " << argv[0] << " <private_key_file> <message_file> <signature_output_file>" << std::endl;
        return 1;
    }

    std::string privateKeyFile = argv[1];
    std::string messageFile = argv[2];
    std::string signatureFile = argv[3];

    try {
        // Load the private key (n and d)
        Integer n, d;
        LoadPrivateKey(privateKeyFile, n, d);

        // Read the message from the file
        std::string message = ReadFileToString(messageFile);

        // Generate the hash (digest) of the message
        Integer digest = GenerateDigest(message);

        // Sign the digest using the private key
        Integer signature = SignDigest(digest, d, n);

        // Save the signature to a file
        SaveSignatureToFile(signatureFile, signature);
        // std::cout<<"n: "<<n<<std::endl<<"d: "<<d<<std::endl<<"message: "<<message<<std::endl<<"signature: "<<signature<<std::endl<<"digest: "<<digest<<std::endl;

        std::cout << "Signature generated and saved to " << signatureFile << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
