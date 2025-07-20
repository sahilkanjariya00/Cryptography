#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/modarith.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;

// Maximum allowed size for n (adjustable based on key size, e.g., 2048 bits = 256 bytes)
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

// Function to decrypt the cipher using c^d mod n
Integer DecryptMessage(const Integer& c, const Integer& d, const Integer& n) {
    return a_exp_b_mod_c(c, d, n);
}

// Function to save the decrypted message to a text file
void SaveDecryptedMessage(const std::string& outputFile, const Integer& decrypted) {
    std::ofstream outFile(outputFile);
    if (!outFile.is_open()) {
        throw std::runtime_error("Could not open output file.");
    }

    size_t byteCount = decrypted.MinEncodedSize();
    SecByteBlock buffer(byteCount);
    decrypted.Encode(buffer.data(), byteCount);
    outFile.write(reinterpret_cast<const char*>(buffer.data()), byteCount);
    outFile.close();
}

// Function to read the cipher from a binary file (with size information)
Integer ReadCipherFromBinaryFile(const std::string& cipherFile) {
    std::ifstream cipherInput(cipherFile, std::ios::binary);
    if (!cipherInput.is_open()) {
        throw std::runtime_error("Could not open cipher file.");
    }

    // Read the cipher size first
    size_t cipherSize;
    cipherInput.read(reinterpret_cast<char*>(&cipherSize), sizeof(cipherSize));

    if (cipherSize > MAX_N_SIZE) {
        throw std::runtime_error("Error: Cipher size exceeds the maximum allowed size.");
    }

    // Now read the actual cipher data
    SecByteBlock cipherBuffer(cipherSize);
    cipherInput.read(reinterpret_cast<char*>(cipherBuffer.data()), cipherSize);

    Integer c;
    c.Decode(cipherBuffer.data(), cipherSize);

    cipherInput.close();
    return c;
}


int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <cipher_file> <private_key_file> <output_file>" << std::endl;
        return 1;
    }

    std::string cipherFile = argv[1];
    std::string privateKeyFile = argv[2];
    std::string outputFile = argv[3];

    try {
        // Load the private key (n and d) from the file
        Integer n, d;
        LoadPrivateKey(privateKeyFile, n, d);

        // Load the cipher from the binary file
        Integer c = ReadCipherFromBinaryFile(cipherFile);

        // Decrypt the message using c^d mod n
        Integer decrypted = DecryptMessage(c, d, n);

        // Save the decrypted message to a text file
        SaveDecryptedMessage(outputFile, decrypted);
        // std::cout<<"d: "<<d<<std::endl<<"n: "<<n<<std::endl<<"cipher: "<<c<<std::endl<<"decrypted: "<<decrypted<<std::endl;
        std::cout << "Decrypted message saved to " << outputFile << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
