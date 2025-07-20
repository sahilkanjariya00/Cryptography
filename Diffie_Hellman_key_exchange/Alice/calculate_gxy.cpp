#include <iostream>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/dh.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;
using namespace std;

// Load binary-encoded key from a file and decode it into a CryptoPP Integer
Integer LoadKeyFromBin(const string& filename) {
    Integer key;
    FileSource file(filename.c_str(), true);
    key.Decode(file, file.MaxRetrievable());  // Decodes the binary content into Integer
    return key;
}

// Function to print Integer in hexadecimal format
void PrintIntegerHex(const string& label, const Integer& value) {
    cout << label << ": ";
    HexEncoder encoder(new FileSink(cout));
    value.DEREncode(encoder);  // Encode the Integer in DER format to hex
    cout << endl;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <private_key_file> <received_public_key_file>" << endl;
        return 1;
    }

    // Load private key and received public key from binary files
    Integer privateKey = LoadKeyFromBin(argv[1]);
    Integer receivedPublicKey = LoadKeyFromBin(argv[2]);

    // Print loaded public and private keys for verification
    // PrintIntegerHex("Private Key", privateKey);
    cout << "Private Key: " << std::hex << privateKey << endl;
    // PrintIntegerHex("Received Public Key", receivedPublicKey);
    cout << "Public Key: " << std::hex << receivedPublicKey << endl;

    // Load prime p and generator g (same p as during key generation)
    Integer p("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
              "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
              "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
              "7EC6F44C42E9A63A36210000000000090563");

    // Calculate g^xy (shared secret)
    Integer sharedSecret = a_exp_b_mod_c(receivedPublicKey, privateKey, p);

    // Output the shared secret in hexadecimal format
    PrintIntegerHex("Shared Secret (g^xy)", sharedSecret);

    return 0;
}
