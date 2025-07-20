#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/files.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;

const size_t MAX_N_SIZE = 256;  // 2048 bits = 256 bytes, adjust based on key size

// Function to generate a large prime number
Integer GeneratePrime(int bitLength) {
    AutoSeededRandomPool rng;
    Integer prime;

    // Keep generating until we find a prime number
    do {
        prime.Randomize(rng, bitLength);  // Generate random number with specified bit length
        prime |= Integer::One();  // Ensure it is odd (since all primes > 2 are odd)
    } while (!IsPrime(prime));  // Test if the number is prime using IsPrime()

    return prime;
}

// Use fixed public exponent (e.g., 65537)
Integer GenerateCoprime(const Integer& phi) {
    Integer e = 65537;  // Common public exponent
    if (GCD(e, phi) != 1) {
        throw std::runtime_error("e is not coprime with φ(n).");
    }
    return e;
}

// Function to save an Integer to a binary file
void SaveIntegerToBinaryFile(std::ofstream& file, const Integer& value) {
    size_t byteCount = value.MinEncodedSize();  // Get the minimum size needed to encode the integer

    // Write size first
    file.write(reinterpret_cast<const char*>(&byteCount), sizeof(byteCount));

    // Encode and write the integer itself
    SecByteBlock buffer(byteCount);
    value.Encode(buffer.data(), byteCount);
    file.write(reinterpret_cast<const char*>(buffer.data()), byteCount);
}

// Function to generate RSA keys manually
void GenerateRSAKeys(const std::string& publicKeyFile, const std::string& privateKeyFile, int bitLength = 2048) {
    AutoSeededRandomPool rng;

    // Step 1: Generate two large prime numbers p and q
    Integer p = GeneratePrime(bitLength / 2);
    Integer q = GeneratePrime(bitLength / 2);

    // Step 2: Compute n = p * q
    Integer n = p * q;

    // Step 3: Compute Euler's Totient φ(n) = (p-1) * (q-1)
    Integer phi = (p - 1) * (q - 1);

    // Step 4: Use a fixed public exponent e
    Integer e = GenerateCoprime(phi);

    // Step 5: Generate the private key d = e^-1 mod φ(n)
    Integer d = e.InverseMod(phi);

    // Step 6: Save the public key (n, e) in binary format
    std::ofstream pubFile(publicKeyFile, std::ios::binary);
    SaveIntegerToBinaryFile(pubFile, n);  // Save n
    SaveIntegerToBinaryFile(pubFile, e);  // Save e
    pubFile.close();

    // Step 7: Save the private key (d) in binary format
    std::ofstream privFile(privateKeyFile, std::ios::binary);
    SaveIntegerToBinaryFile(privFile, n); // Save n
    SaveIntegerToBinaryFile(privFile, d);  // Save d
    privFile.close();

    // std::cout<<"d: "<<d<<std::endl<<"e: "<<e<<std::endl<<"n: "<<n<<std::endl;
    std::cout << "RSA key pair generated successfully in binary format!" << std::endl;
}

int main() {
    std::string publicKeyFile = "public_key.bin";
    std::string privateKeyFile = "private_key.bin";

    try {
        // Generate RSA keys manually
        GenerateRSAKeys(publicKeyFile, privateKeyFile, 2048);  // Use 2048-bit key length
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
