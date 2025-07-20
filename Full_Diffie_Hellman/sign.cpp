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


void Signature(const Integer &p, const Integer &g, const Integer &s, const string &messageFilename)
{
    AutoSeededRandomPool rng;
    Integer r, sigma_1, sigma_2;
    Integer m;

    // Read message and convert to Integer (for simplicity, assuming small messages)
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

    // Ensure r is relatively prime to (p - 1)
    do
    {
        r.Randomize(rng, 2, p - 2);
    } while (GCD(r, p - 1) != Integer::One());

    // Calculate alpha_1 = g^r mod p
    sigma_1 = a_exp_b_mod_c(g, r, p);

    // Calculate alpha_2 = (m - s * alpha_1) * r^(-1) mod (p - 1)
    Integer r_inv = r.InverseMod(p - 1);
    sigma_2 = ((m - s * sigma_1) * r_inv) % (p - 1);

    // Save signature (alpha_1, alpha_2) to file
    FileSink sigFile("signature.bin", true);
    sigma_1.DEREncode(sigFile);  // Save sigma1
    sigma_2.DEREncode(sigFile);  // Save sigma2
    sigFile.MessageEnd();

    cout << "Message is signed " << endl;
}

int main()
{
    Integer p, g, u;
    FileSource pubFile("public_key.bin", true);
    p.BERDecode(pubFile);
    g.BERDecode(pubFile);
    u.BERDecode(pubFile);
    
    Integer x;
    FileSource privFile("private_key.bin", true);
    x.BERDecode(privFile);
    
    
    

    Signature(p, g, x, "data.txt");

    return 0;
}
