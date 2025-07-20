#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

using namespace std;

// Function to initialize the state array and the key array
void initializeStateAndKey(const vector<uint8_t> &key, vector<uint8_t> &S, vector<uint8_t> &K) {
    size_t keyLength = key.size();

    for (int i = 0; i < 256; i++) {
        S[i] = i;
        K[i] = key[i % keyLength];
    }

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + K[i]) % 256;
        swap(S[i], S[j]);
    }
}

// Function to encrypt or decrypt the input data using RC4
vector<uint8_t> rc4EncryptDecrypt(const vector<uint8_t> &input, const vector<uint8_t> &key) {
    vector<uint8_t> S(256), K(256);
    initializeStateAndKey(key, S, K);

    vector<uint8_t> output(input.size());
    int i = 0, j = 0;

    for (size_t n = 0; n < input.size(); n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S[i], S[j]);
        uint8_t k = S[(S[i] + S[j]) % 256];
        output[n] = input[n] ^ k;
    }

    return output;
}

// Function to read the content of a file into a vector
vector<uint8_t> readFile(const string &filename) {
    ifstream file(filename, ios::binary);
    return vector<uint8_t>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

// Function to write a vector to a file
void writeFile(const string &filename, const vector<uint8_t> &data) {
    ofstream file(filename, ios::binary);
    file.write(reinterpret_cast<const char *>(data.data()), data.size());
}

// Function to write data in hexadecimal format to a file
void writeHexFile(const string &filename, const vector<uint8_t> &data) {
    ofstream file(filename);
    for (uint8_t byte : data) {
        file << hex << uppercase << setfill('0') << setw(2) << (int)byte << " ";
    }
    file.close();
}

// Function to read hexadecimal data from a file and convert it to binary
vector<uint8_t> readHexFile(const string &filename) {
    ifstream file(filename);
    vector<uint8_t> binaryData;
    string hexByte;
    
    while (file >> hexByte) {
        uint8_t byte = (uint8_t)stoi(hexByte, nullptr, 16);
        binaryData.push_back(byte);
    }
    
    return binaryData;
}

int main() {
    // 1. Read key and plaintext from their respective files
    vector<uint8_t> key = readFile("key.txt");
    vector<uint8_t> plaintext = readFile("plainText.txt");

    // 2. Encrypt the plaintext and write the ciphertext to cipherText.txt
    vector<uint8_t> ciphertext = rc4EncryptDecrypt(plaintext, key);
    writeHexFile("cipherText.txt", ciphertext);

    cout << "Encryption done! Ciphertext saved to cipherText.txt." << endl;

    // 3. Read key and ciphertext from their respective files
    vector<uint8_t> ciphertextToDecrypt = readHexFile("cipherText.txt");
    vector<uint8_t> keyForDecryption = readFile("key.txt");

    // 4. Decrypt the ciphertext and write the plaintext to decryptedPlainText.txt
    vector<uint8_t> decryptedText = rc4EncryptDecrypt(ciphertextToDecrypt, keyForDecryption);
    writeFile("decryptedPlainText.txt", decryptedText);

    cout << "Decryption done! Decrypted text saved to decryptedPlainText.txt." << endl;

    return 0;
}
