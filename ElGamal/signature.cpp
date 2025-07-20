#include <cryptopp/elgamal.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <private_key_file> <data_file>" << endl;
        return 1;
    }

    const char* privateKeyFile = argv[1];
    const char* dataFile = argv[2];

    try {
        // Initialize random number generator
        AutoSeededRandomPool rng;

        // Load ElGamal private key from the specified binary file
        ElGamal::PrivateKey privateKey;
        FileSource privFile(privateKeyFile, true /* pumpAll */);
        privateKey.Load(privFile);

        // Load the data to be signed from the specified file
        string message;
        FileSource(dataFile, true, new StringSink(message));  // Load text from the specified file

        // Hash the message using SHA-256
        SHA256 hash;
        SecByteBlock digest(hash.DigestSize());
        hash.CalculateDigest(digest, (const byte*)message.data(), message.size());

        // Convert digest to Integer
        Integer H_m(digest, digest.size());

        // ElGamal Signature Parameters
        Integer k, r, s;
        Integer p = privateKey.GetGroupParameters().GetModulus();  // p from the private key
        Integer g = privateKey.GetGroupParameters().GetGenerator(); // g from the private key
        Integer x = privateKey.GetPrivateExponent(); // x from the private key
        Integer p_minus_1 = p - 1;

        // Generate random k such that gcd(k, p-1) = 1
        do {
            k.Randomize(rng, Integer::One(), p_minus_1 - 1);
        } while (EuclideanDomainOf<Integer>().Gcd(k, p_minus_1) != Integer::One());

        // Calculate r = g^k mod p
        r = a_exp_b_mod_c(g, k, p);

        // Calculate s = k^(-1) * (H(m) - x*r) mod (p-1)
        Integer k_inv = k.InverseMod(p_minus_1);
        s = (k_inv * (H_m - x * r)) % p_minus_1;

        // Save the signature (r, s) to a binary file
        FileSink sigFile("signature.bin");
        r.Encode(sigFile, 256);  // Save r as binary
        s.Encode(sigFile, 256);  // Save s as binary

        cout << "Signature generation successful. Signature saved to signature.bin" << endl;
    }
    catch (const Exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
