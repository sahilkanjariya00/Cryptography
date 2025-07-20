#include <iostream>
#include <fstream>
#include <sstream>  // Required for stringstream
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/dh.h>
#include <cryptopp/integer.h>
#include <cryptopp/files.h>

using namespace CryptoPP;
using namespace std;


void Verify(const Integer &p, const Integer &g, const Integer &u, const string &messageFilename, const string &signatureFilename)
{
    Integer sigma_1, sigma_2, m;

    // Read the signature (sigma_1, sigma_2)
    FileSource sigFile("signature.bin", true);
    sigma_1.BERDecode(sigFile);
    sigma_2.BERDecode(sigFile);

    // Read the message and convert to Integer
    ifstream messageFile(messageFilename);
    if (!messageFile)
    {
        cerr << "Error opening message file: " << messageFilename << endl;
        return;
    }

    string message;
    getline(messageFile, message);
    m = Integer((const CryptoPP::byte *)message.data(), message.size());
    messageFile.close();

    // Verify the signature: check if g^m ≡ u^sigma_1 * sigma_1^sigma_2 mod p
    Integer RHS = a_exp_b_mod_c(g, m, p);
    Integer LHS = (a_exp_b_mod_c(u, sigma_1, p) * a_exp_b_mod_c(sigma_1, sigma_2, p)) % p;

    if (LHS == RHS)
    {
        cout << "Signature is valid." << endl;
    }
    else
    {
        cout << "Signature is invalid." << endl;
    }
}

int main()
{
    Integer p, g, u;
    FileSource pubFile("public_key.bin", true);
    p.BERDecode(pubFile);
    g.BERDecode(pubFile);
    u.BERDecode(pubFile);

    Verify(p, g, u, "data.txt", "signature.bin");

    return 0;
}
