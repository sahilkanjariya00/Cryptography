#include <cryptopp/elgamal.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

bool VerifySignature(const ElGamal::PublicKey& publicKey, const string& message, const Integer& r, const Integer& s) {
    // Get group parameters from the public key
    Integer p = publicKey.GetGroupParameters().GetModulus();  // p
    Integer g = publicKey.GetGroupParameters().GetGenerator(); // g
    Integer y = publicKey.GetPublicElement();  // y (the public key component)

    // Verify conditions of r and s
    if (r <= 0 || r >= p || s <= 0 || s >= p - 1) {
        return false; // Invalid signature
    }

    // Hash the message using SHA-256
    SHA256 hash;
    SecByteBlock digest(hash.DigestSize());
    hash.CalculateDigest(digest, (const byte*)message.data(), message.size());

    // Convert digest to Integer
    Integer H_m(digest, digest.size());
    Integer p_minus_1 = p - 1;

    // Calculate v1 = (g^H(m) mod p)
    Integer v1 = a_exp_b_mod_c(g, H_m, p);

    // Calculate v2 = (y^r * r^s mod p)
    Integer v2 = (a_exp_b_mod_c(y, r, p) * a_exp_b_mod_c(r, s, p)) % p;

    // Signature is valid if v1 == v2
    return v1 == v2;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <public_key_file> <data_file> <signature_file>" << endl;
        return 1;
    }

    const char* publicKeyFile = argv[1];
    const char* dataFile = argv[2];
    const char* signatureFile = argv[3];

    try {
        // Load the ElGamal public key from the specified binary file
        ElGamal::PublicKey publicKey;
        FileSource pubFile(publicKeyFile, true /* pumpAll */);
        publicKey.Load(pubFile);

        // Load the decrypted message from the specified text file
        string message;
        FileSource dataFileSource(dataFile, true, new StringSink(message));  // Load the decrypted message

        // Load the signature (r, s) from the specified binary file
        Integer r, s;
        FileSource sigFile(signatureFile, true);
        r.Decode(sigFile, 256);  // Assuming r is 256 bytes
        s.Decode(sigFile, 256);  // Assuming s is 256 bytes

        // Verify the signature
        if (VerifySignature(publicKey, message, r, s)) {
            cout << "Signature verification successful: The signature is valid." << endl;
        } else {
            cout << "Signature verification failed: The signature is invalid." << endl;
        }
    }
    catch (const Exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
