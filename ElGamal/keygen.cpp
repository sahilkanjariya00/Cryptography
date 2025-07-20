#include <cryptopp/elgamal.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

void SavePrivateKey(const ElGamalKeys::PrivateKey& privateKey, const string& filename) {
    FileSink file(filename.c_str(), true);  // 'true' means binary format
    privateKey.Save(file);
}

void SavePublicKey(const ElGamalKeys::PublicKey& publicKey, const string& filename) {
    FileSink file(filename.c_str(), true);  // 'true' means binary format
    publicKey.Save(file);
}

void GenerateElGamalKeys(const string& privKeyFilename, const string& pubKeyFilename) {
    // Initialize random number generator
    AutoSeededRandomPool rng;

    // Generate ElGamal private key
    ElGamalKeys::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024);  // Key size of 1024 bits

    // Generate the corresponding ElGamal public key
    ElGamalKeys::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    // Save the keys in binary format
    SavePrivateKey(privateKey, privKeyFilename);
    SavePublicKey(publicKey, pubKeyFilename);

    // cout << "pravatekye: " << privateKey <<endl<< "public: " << publicKey <<endl;

    cout << "ElGamal keys generated and saved to files: "
         << privKeyFilename << " (private key), "
         << pubKeyFilename << " (public key)" << endl;
}

int main() {
    // Generate and save ElGamal keys to binary files
    GenerateElGamalKeys("private_key.bin", "public_key.bin");

    return 0;
}
