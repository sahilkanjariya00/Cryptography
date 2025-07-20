#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/pssr.h>      // For PSS padding
#include <cryptopp/sha.h>       // For SHA hashing
#include <cryptopp/aes.h>       // For AES encryption
#include <cryptopp/modes.h>     // For AES CBC mode
#include <cryptopp/filters.h>   // For StringSource and FileSink
#include <cryptopp/secblock.h>  // For SecByteBlock
#include <cryptopp/base64.h>    // For Base64 encoding
#include <iostream>
#include <string>

using namespace CryptoPP;
using namespace std;

// Load RSA public key
void LoadPublicKey(const string& filename, RSA::PublicKey& publicKey) {
    FileSource file(filename.c_str(), true);
    publicKey.Load(file);
}

// Load signature from a file
void LoadSignature(const string& signatureFilename, string& signature) {
    FileSource file(signatureFilename.c_str(), true, new StringSink(signature));
}

// Concatenate the data file with the signature
void ConcatenateDataWithSignature(const string& dataFilename, const string& signature, string& concatenatedData) {
    // Load data from file
    string data;
    FileSource file(dataFilename.c_str(), true, new StringSink(data));

    // Concatenate data and signature
    concatenatedData = data + signature;
}

// Encrypt the concatenated data using AES-256
void AESEncrypt(const string& concatenatedData, const SecByteBlock& aesKey, string& cipherText) {
    AutoSeededRandomPool rng;

    // Create AES cipher with CBC mode
    CryptoPP::byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, AES::BLOCKSIZE); //Initialization vector

    CBC_Mode<AES>::Encryption aesEncryptor;
    aesEncryptor.SetKeyWithIV(aesKey, aesKey.size(), iv);

    // Encrypt data
    StringSource ss(concatenatedData, true, new StreamTransformationFilter(aesEncryptor, new StringSink(cipherText)));

    // Prepend IV to the ciphertext
    cipherText = string(reinterpret_cast<const char*>(iv), AES::BLOCKSIZE) + cipherText;
}

// Encrypt the AES session key using RSA
void RSAEncryptSessionKey(const SecByteBlock& aesKey, const RSA::PublicKey& publicKey, string& encryptedSessionKey) {
    AutoSeededRandomPool rng;

    // RSA Encryptor SHA-1
    RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);

    // Encrypt AES session key
    StringSource ss(aesKey, aesKey.size(), true, new PK_EncryptorFilter(rng, rsaEncryptor, new StringSink(encryptedSessionKey)));
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        cerr << "Usage: " << argv[0] << " <public_key.pem> <data_file> <signature_file> <output_prefix>" << endl;
        return 1;
    }

    // File names
    string pubKeyFilename = argv[1];   // Public key (for encrypting AES session key)
    string dataFilename = argv[2];     // Data file to be encrypted
    string signatureFilename = argv[3]; // Signature file to concatenate
    string outputPrefix = argv[4];     // Output prefix for the encrypted files
    string encryptedDataFilename = outputPrefix + "_data.bin";  // Output for encrypted data
    string encryptedKeyFilename = outputPrefix + "_key.bin";    // Output for encrypted AES key

    // Load RSA public key (for encrypting AES key)
    RSA::PublicKey publicKey;
    LoadPublicKey(pubKeyFilename, publicKey);

    // Load signature from file
    string signature;
    LoadSignature(signatureFilename, signature);

    // Step 1: Concatenate data with signature
    string concatenatedData;
    ConcatenateDataWithSignature(dataFilename, signature, concatenatedData);

    // Step 2: Generate AES-256 session key
    AutoSeededRandomPool rng;
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);  // AES::DEFAULT_KEYLENGTH is 32 bytes for AES-256
    rng.GenerateBlock(aesKey, aesKey.size());

    // Step 3: Encrypt concatenated data with AES
    string encryptedData;
    AESEncrypt(concatenatedData, aesKey, encryptedData);

    // Step 4: Encrypt AES session key with recipient's RSA public key
    string encryptedSessionKey;
    RSAEncryptSessionKey(aesKey, publicKey, encryptedSessionKey);

    // Step 5: Write the encrypted data and encrypted session key to separate files
    FileSink encryptedDataFile(encryptedDataFilename.c_str());
    encryptedDataFile.Put(reinterpret_cast<const CryptoPP::byte*>(encryptedData.data()), encryptedData.size());

    FileSink encryptedKeyFile(encryptedKeyFilename.c_str());
    encryptedKeyFile.Put(reinterpret_cast<const CryptoPP::byte*>(encryptedSessionKey.data()), encryptedSessionKey.size());

    cout << "Encryption successful! Encrypted data saved to " << encryptedDataFilename
         << " and encrypted session key saved to " << encryptedKeyFilename << endl;

    return 0;
}

