#!/bin/bash

# Store the number of iterations in a variable
ITERATIONS=10
TOTAL_EXECUTION_TIME=0

# Variables to accumulate execution times for each process
# TOTAL_KEYGEN_TIME=0
# TOTAL_ENCRYPT_TIME=0
# TOTAL_DECRYPT_TIME=0

for (( i=1; i<=ITERATIONS; i++ ))
        do  
            echo "Iteration: $i"
            # Generate random data of a specified length (less than 128 characters)
            RANDOM_DATA=$(openssl rand -base64 96 | cut -c1-127)

            # Define the output file
            OUTPUT_FILE="random_data.txt"

            # Store the generated random data in the txt file
            echo "$RANDOM_DATA" > "$OUTPUT_FILE"

            # Print a message to confirm the data is saved
            echo "Random data (less than 128 characters) saved to $OUTPUT_FILE"





            # Compile the keygen.cpp file
            echo "Compiling keygen.cpp..."
            g++ keygen.cpp -o keygen -lcryptopp

            # Check if keygen compilation was successful
            if [ $? -eq 0 ]; then
                echo "Compilation of keygen.cpp successful."

                # Run the keygen executable and capture the output
                KEYGEN_OUTPUT=$(./keygen)
                echo $KEYGEN_OUTPUT
                KEYGEN_TIME=$(echo "$KEYGEN_OUTPUT" | grep -oP 'Execution Cost = \K[0-9.]+')
                TOTAL_EXECUTION_TIME=$(echo "$TOTAL_EXECUTION_TIME + $KEYGEN_TIME" | bc)

                # Compile the encrypt.cpp file
                echo "Compiling encrypt.cpp..."
                g++ encrypt.cpp -o encrypt -lcryptopp

                # Check if encrypt compilation was successful
                if [ $? -eq 0 ]; then
                    echo "Compilation of encrypt.cpp successful."

                    # Run the encrypt executable and capture the output
                    ENCRYPT_OUTPUT=$(./encrypt public_key.bin random_data.txt)
                    echo $ENCRYPT_OUTPUT
                    ENCRYPT_TIME=$(echo "$ENCRYPT_OUTPUT" | grep -oP 'Execution Cost = \K[0-9.]+')
                    TOTAL_EXECUTION_TIME=$(echo "$TOTAL_EXECUTION_TIME + $ENCRYPT_TIME" | bc)

                    # Compile the decrypt.cpp file
                    echo "Compiling decrypt.cpp..."
                    g++ decrypt.cpp -o decrypt -lcryptopp

                    # Check if decrypt compilation was successful
                    if [ $? -eq 0 ]; then
                        echo "Compilation of decrypt.cpp successful."

                        # Run the decrypt executable and capture the output
                        DECRYPT_OUTPUT=$(./decrypt private_key.bin cipher.bin)
                        echo $DECRYPT_OUTPUT
                        DECRYPT_TIME=$(echo "$DECRYPT_OUTPUT" | grep -oP 'Execution Cost = \K[0-9.]+')
                        TOTAL_EXECUTION_TIME=$(echo "$TOTAL_EXECUTION_TIME + $DECRYPT_TIME" | bc)

                    else
                        echo "Compilation of decrypt.cpp failed."
                    fi

                else
                    echo "Compilation of encrypt.cpp failed."
                fi

            else
                echo "Compilation of keygen.cpp failed."
            fi
        echo "---------------------------------------------------------------------------------------------------"
    done
# Calculate the average times
AVERAGE_EXECUTION_TIME=$(echo "$TOTAL_EXECUTION_TIME / $ITERATIONS" | bc -l)

# Print the total and average times
echo "All $ITERATIONS iterations completed successfully."
echo "Total RSA encryption time: $TOTAL_EXECUTION_TIME ms"
echo "Average RSA encryption time: $AVERAGE_EXECUTION_TIME ms"