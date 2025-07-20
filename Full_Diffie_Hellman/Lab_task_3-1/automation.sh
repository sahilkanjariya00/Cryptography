#!/bin/bash

# Number of iterations
iterations=100

# Loop for the given number of iterations
for ((i=1; i<=iterations; i++))
do
    echo "Iteration $i"

    # Step 1: Generate random data and store it inside data.txt
    # Using openssl to generate random text
    cat /dev/urandom | tr -dc 'a-z0-9' | head -c 128 > data.txt
    echo "Generated random data and stored in data.txt"

    # Step 2: Execute encryption
    ./encryption
    if [ $? -ne 0 ]; then
        echo "Encryption failed in iteration $i."
        exit 1
    else
        echo "Encryption completed successfully in iteration $i."
    fi

    # Step 3: Execute decryption
    ./decryption
    if [ $? -ne 0 ]; then
        echo "Decryption failed in iteration $i."
        exit 1
    else
        echo "Decryption completed successfully in iteration $i."
    fi

    # Step 4: Generate md5sum of data.txt and decrypted_message.txt
    md5_original=$(md5sum data.txt | awk '{print $1}')
    md5_decrypted=$(md5sum decrypted_message.txt | awk '{print $1}')

    echo "MD5 of data.txt: $md5_original"
    echo "MD5 of decrypted_message.txt: $md5_decrypted"

    # Step 5: Compare the md5sum values
    if [ "$md5_original" == "$md5_decrypted" ]; then
        echo "MD5 hashes match for iteration $i. Encryption and Decryption were successful."
    else
        echo "MD5 hashes do not match for iteration $i. There was an issue with the encryption/decryption process."
        exit 1
    fi

    echo "-----------------------"
done

echo "All iterations completed successfully."


