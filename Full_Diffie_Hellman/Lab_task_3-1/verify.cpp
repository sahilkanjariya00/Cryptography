#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>   // For modular arithmetic
#include <cryptopp/files.h>      // For file I/O
#include <cryptopp/hex.h>        // For hex encoding/decoding
#include <iostream>
#include <fstream>
#include <sstream>               // For reading entire file

using namespace CryptoPP;
using namespace std;

int main() {
    // Step 1: Read the signature (sigma1, sigma2) from the signature.bin file
    Integer sigma1, sigma2;
    FileSource sigFile("signature.bin", true);
    sigma1.BERDecode(sigFile);
    sigma2.BERDecode(sigFile);

    // Print the values of sigma1 and sigma2
    cout << "Signature (sigma1, sigma2):" << endl;
    cout << "sigma1: " << sigma1 << endl;
    cout << "sigma2: " << sigma2 << endl;

    // Step 2: Read the public key (g, p, h) from the public_key.bin file
    Integer g, p, h;
    FileSource pubFile("public_key.bin", true);
    p.BERDecode(pubFile);
    g.BERDecode(pubFile);
    h.BERDecode(pubFile);

    // Print the values of g, p, and h (public key)
    cout << "Public Key (g, p, h):" << endl;
    cout << "g: " << g << endl;
    cout << "p: " << p << endl;
    cout << "h: " << h << endl;

    // Step 3: Read the decrypted message from the decrypted_message.txt file
    ifstream infile("decrypted_message.txt");
    stringstream buffer;
    buffer << infile.rdbuf();  // Read entire file content into a stringstream
    string message = buffer.str();
    infile.close();

    // Convert the message string to an integer M
    Integer m((const byte*)message.data(), message.size());

    // Print the value of m
    cout << "Decrypted Message M: " << m << endl;

    // Step 4: Break down into three parts
    // 4.1 Calculate u^sigma1 mod p
    Integer step1 = a_exp_b_mod_c(h, sigma1, p);
    cout << "h^sigma1 mod p: " << step1 << endl;

    // 4.2 Calculate sigma1^sigma2 mod p
    Integer step2 = a_exp_b_mod_c(sigma1, sigma2, p);
    cout << "sigma1^sigma2 mod p: " << step2 << endl;

    // 4.3 Calculate (u^sigma1 * sigma1^sigma2) mod p
    Integer step4 = (step1 * step2) % p;
    cout << "(h^sigma1 * sigma1^sigma2) mod p: " << step4 << endl;

    // Step 5: Calculate g^m mod p
    Integer step5 = a_exp_b_mod_c(g, m, p);
    cout << "g^m mod p: " << step5 << endl;

    // Step 6: Compare step 4 and step 5 results
    if (step4 == step5) {
        cout << "Signature is valid. Verification successful!" << endl;
    } else {
        cout << "Signature is invalid. Verification failed!" << endl;
    }

    return 0;
}


