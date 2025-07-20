#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <iostream>
#include <string>

using namespace CryptoPP;
using namespace std;

// Load RSA private key
void LoadPrivateKey(const string& filename, RSA::PrivateKey& privateKey) {
    FileSource file(filename.c_str(), true);
    privateKey.Load(file);
}

// Decrypt the AES session key using RSA
void RSADecryptSessionKey(const string& encryptedSessionKey, const RSA::PrivateKey& privateKey, SecByteBlock& aesKey) {
    AutoSeededRandomPool rng;

    // RSA Decryptor using Optimal Asymmetric Encryption Padding
    RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateKey);

    // Decrypt the session key
    StringSource ss(encryptedSessionKey, true, new PK_DecryptorFilter(rng, rsaDecryptor, new ArraySink(aesKey, aesKey.size())));
}

// AES Decrypt function
void AESDecrypt(const string& encryptedData, const SecByteBlock& aesKey, string& concatenatedData) {
    AutoSeededRandomPool rng;

    // Extract the IV from the beginning of the encrypted data
    const CryptoPP::byte* iv = reinterpret_cast<const CryptoPP::byte*>(encryptedData.data());

    // Set up AES decryption with CBC mode
    CBC_Mode<AES>::Decryption aesDecryptor;
    aesDecryptor.SetKeyWithIV(aesKey, aesKey.size(), iv);

    // Decrypt the remaining data after the IV
    StringSource ss(encryptedData.substr(AES::BLOCKSIZE), true,
                    new StreamTransformationFilter(aesDecryptor, new StringSink(concatenatedData)));
}

// Function to separate data and signature
void SeparateDataAndSignature(const string& concatenatedData, string& data, string& signature) {
    size_t signatureSize = 256;  // Adjust based on your RSA key size
    size_t dataSize = concatenatedData.size() - signatureSize;

    if (dataSize > 0 && signatureSize > 0 && concatenatedData.size() == (dataSize + signatureSize)) {
        data = concatenatedData.substr(0, dataSize);
        signature = concatenatedData.substr(dataSize, signatureSize);
    } else {
        cerr << "Error: Invalid concatenated data size or signature size." << endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        cerr << "Usage: " << argv[0] << " <private_key.pem> <encrypted_data.bin> <encrypted_key.bin> <output_prefix>" << endl;
        return 1;
    }

    // File names
    string privKeyFilename = argv[1];
    string encryptedDataFilename = argv[2];
    string encryptedKeyFilename = argv[3];
    string outputPrefix = argv[4];

    // Output file names
    string decryptedDataFilename = outputPrefix + "_data.txt";
    string signatureFilename = outputPrefix + "_signature.bin";

    // Load RSA private key
    RSA::PrivateKey privateKey;
    LoadPrivateKey(privKeyFilename, privateKey);

    // Read the encrypted AES session key
    string encryptedSessionKey;
    FileSource keyFile(encryptedKeyFilename.c_str(), true, new StringSink(encryptedSessionKey));

    // Decrypt the AES session key using the RSA private key
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
    RSADecryptSessionKey(encryptedSessionKey, privateKey, aesKey);

    // Read the encrypted data
    string encryptedData;
    FileSource dataFile(encryptedDataFilename.c_str(), true, new StringSink(encryptedData));

    // Decrypt the concatenated data (data + signature) using AES
    string concatenatedData;
    AESDecrypt(encryptedData, aesKey, concatenatedData);

    // Separate the decrypted plaintext data and signature
    string data, signature;
    SeparateDataAndSignature(concatenatedData, data, signature);

    // Write the decrypted data and signature to separate files
    FileSink decryptedDataFile(decryptedDataFilename.c_str());
    decryptedDataFile.Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());

    FileSink signatureFile(signatureFilename.c_str());
    signatureFile.Put(reinterpret_cast<const CryptoPP::byte*>(signature.data()), signature.size());

    cout << "Decryption successful! Decrypted data saved to " << decryptedDataFilename
         << " and extracted signature saved to " << signatureFilename << endl;

    return 0;
}

