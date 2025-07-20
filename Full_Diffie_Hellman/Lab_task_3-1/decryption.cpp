#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>   // For modular arithmetic
#include <cryptopp/files.h>      // For file I/O
#include <cryptopp/hex.h>        // For hex encoding/decoding
#include <iostream>
#include <fstream>

using namespace CryptoPP;
using namespace std;

int main() {
    // Step 1: Read the ciphertext (C1, C2) from the file
    Integer C1, C2;
    FileSource cipherFile("ciphertext.bin", true);
    C1.BERDecode(cipherFile);
    C2.BERDecode(cipherFile);

    // Print the values of C1 and C2
    cout << "Ciphertext (C1, C2):" << endl;
    cout << "C1: " << C1 << endl;
    cout << "C2: " << C2 << endl;

    // Step 2: Read the private key (x) from the file
    Integer x;
    FileSource privFile("private_key.bin", true);
    x.BERDecode(privFile);

    // Print the value of private key x
    cout << "Private Key x: " << x << endl;

    // Step 3: Read public parameter p from the public key file
    Integer p;
    FileSource pubFile("public_key.bin", true);
    p.BERDecode(pubFile);  // We only need p from the public key

    // Step 4: Compute the shared secret s = C1^x mod p
    Integer s = a_exp_b_mod_c(C1, x, p);
    cout << "Shared Secret s: " << s << endl;

    // Step 5: Compute the modular inverse of s mod p
    Integer s_inv = s.InverseMod(p);
    cout << "Modular Inverse s^-1: " << s_inv << endl;

    // Step 6: Compute the original message M = C2 * s^-1 mod p
    Integer M = (C2 * s_inv) % p;
    cout << "Decrypted Message M (as Integer): " << M << endl;

    // Step 7: Convert the Integer message back to string and save it
    string decryptedMessage;
    size_t encodedSize = M.MinEncodedSize();
    decryptedMessage.resize(encodedSize);
    M.Encode((byte*)decryptedMessage.data(), decryptedMessage.size());

    // Step 8: Read the original "data.txt" to check for newline formatting
    ifstream originalFile("data.txt");
    string originalMessage((istreambuf_iterator<char>(originalFile)),
                            istreambuf_iterator<char>());
    originalFile.close();

    // Step 9: Write the decrypted message to "decrypted_message.txt"
    ofstream msgFile("decrypted_message.txt");

    // Check if the last character of the original message is a newline
    if (!originalMessage.empty() && originalMessage.back() == '\n') {
        msgFile << decryptedMessage;  // Don't add another newline; it's already included in decryptedMessage
    } else {
        msgFile << decryptedMessage;  // No newline if the original didn't have one
    }

    msgFile.close();

    // Save shared secret s
    FileSink sharedFile("shared_secret.bin", true);
    s.DEREncode(sharedFile);
    sharedFile.MessageEnd();

    cout << "Decryption complete. Shared secret saved in 'shared_secret.bin' and decrypted message saved in 'decrypted_message.txt'." << endl;

    return 0;
}


