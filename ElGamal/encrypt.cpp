#include <cryptopp/elgamal.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>

using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <public_key_file> <data_file>" << endl;
        return 1;
    }

    const char* publicKeyFile = argv[1];
    const char* dataFile = argv[2];

    try {
        // Initialize random number generator
        AutoSeededRandomPool rng;

        // Load the public key from the specified binary file
        ElGamal::Encryptor encryptor;
        FileSource pubFile(publicKeyFile, true /* pumpAll */);  // Load in binary
        encryptor.AccessKey().Load(pubFile);

        // Load the plaintext message from the specified file
        string plain;
        FileSource(dataFile, true, new StringSink(plain));  // Load text from data.txt

        // Encrypt the message
        string cipher;
        StringSource(plain, true,
            new PK_EncryptorFilter(rng, encryptor, new StringSink(cipher))
        );

        // Save the cipher text to a binary file
        FileSink cipherFile("cipher.bin");
        cipherFile.Put(reinterpret_cast<const byte*>(cipher.data()), cipher.size());

        cout << "Encryption successful. Cipher saved to cipher.bin" << endl;
    }
    catch (const Exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
