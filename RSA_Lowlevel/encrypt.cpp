#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/files.h>
#include <iostream>
#include <string>
#include <ctime> //time

using namespace CryptoPP;

void Encrypt(const std::string& pubKeyFile, const std::string& dataFile, const std::string& cipherFile) {
    // Read public key (e, n) from binary file
    Integer e, n;
    FileSource pubFile(pubKeyFile.c_str(), true); //FileSource is a class that reads data from a file.
    e.BERDecode(pubFile);//using the Basic Encoding Rules (BER) format.
    n.BERDecode(pubFile);

    // Read plaintext from data file
    std::ifstream in(dataFile);//ifstream- an input file stream used to read data from files.
    std::string message;
    std::getline(in, message);//reads a single line from the file stream in into the message string.
    in.close();

    // Convert message to Integer (plaintext)
    Integer m((const byte*)message.data(), message.size());//message.data() returns a pointer to the raw byte data(typecast)
    if(m>n){
      m=m%n;
      }
    // Perform encryption: C = m^e mod n
    clock_t startTime, endTime; //time
    double elapsed_time; //time
    double avgTimeTaken, totalTimeTaken = 0.0; //time
    startTime = clock();

    Integer C = a_exp_b_mod_c(m, e, n);

    endTime = clock();
    elapsed_time = static_cast<double>(endTime - startTime)/CLOCKS_PER_SEC*1000;
    totalTimeTaken = (totalTimeTaken + elapsed_time);
    // avgTimeTaken = (totalTimeTaken / n);
    std::cout << "Execution Cost = " << totalTimeTaken << " ms" << std::endl;

    // Write ciphertext to file in binary format
    FileSink cipherSink(cipherFile.c_str());
    C.DEREncode(cipherSink);
    cipherSink.MessageEnd();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: ./encrypt <public_key_file> <data_file>\n";
        return 1;
    }

    Encrypt(argv[1], argv[2], "cipher.bin");
    return 0;
}

