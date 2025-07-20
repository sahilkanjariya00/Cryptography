#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <iostream>
#include <stdio.h>

using namespace CryptoPP;
using namespace std;

void SavePublicKey(const RSA::PublicKey& PublicKey, const string& filename) {
    // Save the public key in binary format
    FileSink file(filename.c_str());
    PublicKey.Save(file);
}

void SavePrivateKey(const RSA::PrivateKey& PrivateKey, const string& filename) {
    // Save the private key in binary format
    FileSink file(filename.c_str());
    PrivateKey.Save(file);
}

void GenerateRSAKeys(unsigned int keySize, const string& pubKeyFilename, const string& privKeyFilename) {
    // Random number generator for key generation
    AutoSeededRandomPool rng;

    // Generate RSA private key
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keySize);

    // Get the corresponding RSA public key
    RSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);

    // Save the public and private keys to binary files
    SavePublicKey(publicKey, pubKeyFilename);
    SavePrivateKey(privateKey, privKeyFilename);

    cout << "RSA keys generated and saved to files." << endl;
}

int main(int argc, char* argv[]) {
    // Specify the key size (in bits) and output filenames
    unsigned int keySize = 2048; // Key size in bits
    if(argc != 3){
	    cerr << "Enter: " << argv[0] <<" <private_key.bin> <public_key.bin>"<<endl;
	    return 1;
    }
    string pubKeyFilename = argv[2];
    string privKeyFilename = argv[1];

    // Generate the keys and save them to files
    GenerateRSAKeys(keySize, pubKeyFilename, privKeyFilename);

    return 0;
}

