#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/files.h>
#include <iostream>
#include <ctime> //time

using namespace CryptoPP;



void KeyGen(const std::string& pubKeyFile, const std::string& privKeyFile) {
    clock_t startTime, endTime; //time
    double elapsed_time; //time
    double avgTimeTaken, totalTimeTaken = 0.0; //time
    startTime = clock();

    AutoSeededRandomPool rng;  //class provided by the Crypto++ library that is responsible for generating cryptographically secure random numbers.

    // Generate two large primes
    PrimeAndGenerator primeGen;
    //1 tells the function to generate a safe prime.
    //rng is the random number generator.
    //primeBits is the bit size of the prime number.
    //generatorBits is the bit size of the generator, which in RSA isn't typically needed.
    primeGen.Generate(1, rng, 1024, 1023);
    Integer p = primeGen.Prime();
    primeGen.Generate(1, rng, 1024, 1023);
    Integer q = primeGen.Prime();
    
    while(p==q){
        //p = primeGen.Prime();
        q = primeGen.Prime();
    }

    // Compute n = p * q
    //used in both encryption and decryption. The size of n dictates the security strength of the cryptosystem. one way fuction.
    Integer n = p * q;
    
    // Compute phi(n) = (p - 1)(q - 1)
    Integer phi_n = (p - 1) * (q - 1); // ---

    // Choose e such that 1 < d < phi_n and gcd(d, phi_n) = 1
    Integer d;
    do {
        d.Randomize(rng, Integer::One(), phi_n - 1);
    } while (!RelativelyPrime(d, phi_n));

    // Calculate public key e
    Integer e = d.InverseMod(phi_n);

    endTime = clock();
    elapsed_time = static_cast<double>(endTime - startTime)/CLOCKS_PER_SEC*1000;
    totalTimeTaken = (totalTimeTaken + elapsed_time);
    // avgTimeTaken = (totalTimeTaken / n);
    std::cout << "Execution Cost = " << totalTimeTaken << " ms" << std::endl;

    // Write public key to file (e, n) in binary format
    {
        FileSink pub(pubKeyFile.c_str());//FileSink is a class that writes data to a file.
        e.DEREncode(pub); //encode integers(e,n) in DER (Distinguished Encoding Rules) format.
        n.DEREncode(pub);
        pub.MessageEnd();// signals the end of the message or stream
    }

    // Write private key to file (d, n) in binary format
    {
        FileSink priv(privKeyFile.c_str());
        d.DEREncode(priv);
        n.DEREncode(priv);
        priv.MessageEnd();
    }
}

int main() {
    try {
        KeyGen("public_key.bin", "private_key.bin");
        std::cout << "Keys generated successfully.\n";
    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}

