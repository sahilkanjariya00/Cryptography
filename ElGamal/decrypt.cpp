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
        cerr << "Usage: " << argv[0] << " <private_key_file> <cipher_file>" << endl;
        return 1;
    }

    const char* privateKeyFile = argv[1];
    const char* cipherFile = argv[2];

    try {
        // Initialize random number generator
        AutoSeededRandomPool rng;

        // Load the private key from the specified binary file
        ElGamal::Decryptor decryptor;
        FileSource privFile(privateKeyFile, true /* pumpAll */);  // Load in binary
        decryptor.AccessKey().Load(privFile);

        // Load the cipher text from the specified file
        string cipher;
        FileSource cipherFileSource(cipherFile, true, new StringSink(cipher));  // Load cipher from the specified file

        // Decrypt the message
        string recovered;
        StringSource(cipher, true,
            new PK_DecryptorFilter(rng, decryptor, new StringSink(recovered))
        );

        // Save the decrypted text to a file
        FileSink outputFile("dtext.txt");
        outputFile.Put(reinterpret_cast<const byte*>(recovered.data()), recovered.size());

        cout << "Decryption successful. Decrypted text saved to dtext.txt" << endl;
    }
    catch (const Exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
