For generating the pair of rsa key:
g++ -o generate_keys generate_keys.cpp -lssl -lcrypto

For generating digital signature:
g++ -o sign_message sign_message.cpp -lssl -lcrypto

For encryption message and session key:
g++ -o encrypt_message encrypt_message.cpp -lssl -lcrypto

For decryption of message and session key:
g++ -o decrypt_data decrypt_data.cpp -lssl -lcrypto

For signature verification:
g++ -o verify_signature verify_signature.cpp -lssl -lcrypto
