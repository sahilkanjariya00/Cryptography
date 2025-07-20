#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/pssr.h>      // For PSS padding
#include <cryptopp/sha.h>       // For SHA hashing
#include <cryptopp/secblock.h>  // For SecByteBlock
#include <cryptopp/filters.h>   // For StringSource and SignatureVerificationFilter
#include <iostream>
#include <string>

using namespace CryptoPP;
using namespace std;

// Load RSA public key from file
void LoadPublicKey(const string& filename, RSA::PublicKey& publicKey) {
    FileSource file(filename.c_str(), true);
    publicKey.Load(file);
}

// Verify the signature using the sender's RSA public key
bool VerifySignature(const string& dataFilename, const string& signatureFilename, const RSA::PublicKey& publicKey) {
    // Load data from file
    string data;
    FileSource(dataFilename.c_str(), true, new StringSink(data));

    // Load signature from file
    string signature;
    FileSource(signatureFilename.c_str(), true, new StringSink(signature));

    // Create PSS verifier
    RSASS<PSSR, SHA256>::Verifier verifier(publicKey);

    // Verify signature
    bool result = false;
    StringSource ss(signature + data, true,
        new SignatureVerificationFilter(
            verifier,
            new ArraySink(reinterpret_cast<CryptoPP::byte*>(&result), sizeof(result))
        )
    );

    return result;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <public_key.pem> <data_file> <signature_file>" << endl;
        return 1;
    }

    // File names
    string pubKeyFilename = argv[1];    // Public key (for signature verification)
    string dataFilename = argv[2];      // Data file whose signature needs verification
    string signatureFilename = argv[3]; // Signature file

    // Load RSA public key
    RSA::PublicKey publicKey;
    LoadPublicKey(pubKeyFilename, publicKey);

    // Verify the signature
    bool isValid = VerifySignature(dataFilename, signatureFilename, publicKey);

    if (isValid) {
        cout << "Signature is valid." << endl;
    } else {
        cout << "Signature is invalid." << endl;
    }

    return 0;
}

