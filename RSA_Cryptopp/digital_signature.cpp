#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/pssr.h>  // For PSS padding (Probabilistic Signature Scheme) a secure padding schema for signing
#include <cryptopp/sha.h>   // For SHA hashing
#include <iostream>
#include <string>

using namespace CryptoPP;
using namespace std;

void LoadPrivateKey(const string& filename, RSA::PrivateKey& privateKey) {
    // Load the private key from the file
    FileSource file(filename.c_str(), true);
    privateKey.Load(file);
}

void GenerateSignature(const string& dataFilename, const RSA::PrivateKey& privateKey, const string& signatureFilename) {
    // Load data from file
    string data;
    FileSource file(dataFilename.c_str(), true, new StringSink(data));

    // Create an instance of AutoSeededRandomPool
    AutoSeededRandomPool rng;

    // Create a PSS (Probabilistic Signature Scheme) signer
    RSASS<PSSR, SHA256>::Signer signer(privateKey);

    // Create a signature for the data
    string signature;
    StringSource ss(data, true, new SignerFilter(rng, signer, new StringSink(signature)));

    // Save the signature to a file
    FileSink sigFile(signatureFilename.c_str());
    sigFile.Put(reinterpret_cast<const CryptoPP::byte*>(signature.data()), signature.size());
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <private_key.bin> <data_file>" << std::endl;
        return 1;
    }

    // Filenames
    string privKeyFilename = argv[1]; // Private key file
    string dataFilename = argv[2];    // Data file to sign
    string signatureFilename = "signature.bin";  // Signature output file

    // Load RSA private key
    RSA::PrivateKey privateKey;
    LoadPrivateKey(privKeyFilename, privateKey);

    // Generate and save the signature
    GenerateSignature(dataFilename, privateKey, signatureFilename);

    return 0;
}

