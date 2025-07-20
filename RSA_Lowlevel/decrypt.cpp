#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/files.h>
#include <iostream>
#include <string>
#include <ctime> //time

using namespace CryptoPP;

void Decrypt(const std::string& privKeyFile, const std::string& cipherFile, const std::string& outFile) {
    // Read private key (d, n) from binary file
    Integer d, n;
    FileSource privFile(privKeyFile.c_str(), true);
    d.BERDecode(privFile);
    n.BERDecode(privFile);

    // Read ciphertext from binary file
    Integer C;
    FileSource cipherSource(cipherFile.c_str(), true);
    C.BERDecode(cipherSource);

    // Perform decryption: m = C^d mod n
    clock_t startTime, endTime; //time
    double elapsed_time; //time
    double avgTimeTaken, totalTimeTaken = 0.0; //time
    startTime = clock();

    Integer m = a_exp_b_mod_c(C, d, n);

    endTime = clock();
    elapsed_time = static_cast<double>(endTime - startTime)/CLOCKS_PER_SEC*1000;
    totalTimeTaken = (totalTimeTaken + elapsed_time);
    std::cout << "Execution Cost = " << totalTimeTaken << " ms" << std::endl;

    // Convert the decrypted integer back to string (plaintext)
    
    std::string decodedMessage(m.MinEncodedSize(), '\0');//MinEncodedSize() is a method of the Integer class that returns the minimum number of bytes required to encode the integer m.
    
    m.Encode((byte*)decodedMessage.data(), decodedMessage.size());//Encode is a method in the Integer class that encodes the value of m into a byte array
    //

    // Write decrypted message to file
    std::ofstream out(outFile);
    out << decodedMessage;
    out.close();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: ./decrypt <private_key_file> <cipher_file>\n";
        return 1;
    }

    Decrypt(argv[1], argv[2], "dec_msg.txt");
    return 0;
}

