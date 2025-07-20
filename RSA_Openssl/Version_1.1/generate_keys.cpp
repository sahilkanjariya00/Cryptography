#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <memory>
#include <string>
using namespace std;

// Function to handle errors
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to generate RSA keys and save them to files
void generate_keys(const string& private_key_filename, const string& public_key_filename) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Create a new EVP_PKEY object
    unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(), EVP_PKEY_free);
    if (!pkey) {
        handleErrors();
    }

    // Create a new EVP_PKEY_CTX for RSA key generation
    unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), EVP_PKEY_CTX_free);
    if (!pctx) {
        handleErrors();
    }

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        handleErrors();
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx.get(), 2048) <= 0) {
        handleErrors();
    }

    // Create a raw EVP_PKEY pointer to hold the generated key
    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey_raw) <= 0) {
        handleErrors();
    }

    // Assign the raw key to the unique pointer
    pkey.reset(pkey_raw);

    // Save private key
    FILE* private_file = fopen(private_key_filename.c_str(), "wb");
    if (!private_file) {
        cerr << "Unable to open file for writing private key: " << private_key_filename << endl;
        handleErrors();
    }

    if (PEM_write_PrivateKey(private_file, pkey.get(), NULL, NULL, 0, NULL, NULL) != 1) {
        cerr << "Error writing private key to file" << endl;
        handleErrors();
    }
    fclose(private_file);

    // Save public key
    FILE* public_file = fopen(public_key_filename.c_str(), "wb");
    if (!public_file) {
        cerr << "Unable to open file for writing public key: " << public_key_filename << endl;
        handleErrors();
    }

    if (PEM_write_PUBKEY(public_file, pkey.get()) != 1) {
        cerr << "Error writing public key to file" << endl;
        handleErrors();
    }
    fclose(public_file);
}

int main() {
    // Set filenames for the keys
    string private_key_filename = "Alice's_private_key.pem";
    string public_key_filename = "Alice's_public_key.pem";
    string private_key_filename_2 = "Bob's_private_key.pem";
    string public_key_filename_2 = "Bob's_public_key.pem";

    // Generate and save the keys
    generate_keys(private_key_filename, public_key_filename);
    generate_keys(private_key_filename_2, public_key_filename_2);

    cout << "RSA keys generated and saved successfully." << endl;

    return 0;
}

