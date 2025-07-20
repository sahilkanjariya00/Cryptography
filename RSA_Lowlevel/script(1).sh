#!/bin/bash

ITERATIONS=10

# Variable to accumulate execution time
TOTAL_EXECUTION_TIME=0

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



            echo "Compiling sign.cpp..."
            g++ sign.cpp -o sign -lcryptopp

            # Check if the compilation was successful
            if [ $? -eq 0 ]; then
                echo "Compilation of sign.cpp successful."

                # Run the sign executable with the private_key.bin and random_data.txt files
                # Run the sign executable and capture the output in a variable
                OUTPUT=$(./sign private_key.bin random_data.txt)
                echo $OUTPUT

                # Extract the execution cost from the output (assuming it's always formatted like "Execution Cost = 4.487 ms")
                EXECUTION_TIME=$(echo "$OUTPUT" | grep -oP 'Execution Cost = \K[0-9.]+')

                # Add the execution time to the total (converting ms to seconds for easier summation, optional)
                TOTAL_EXECUTION_TIME=$(echo "$TOTAL_EXECUTION_TIME + $EXECUTION_TIME" | bc)

                # Check if the sign program ran successfully
                if [ $? -eq 0 ]; then
                    echo "Sign program executed successfully."

                    # Compile the verify.cpp file
                    echo "Compiling verify.cpp..."
                    g++ verify.cpp -o verify -lcryptopp

                    # Check if the compilation was successful
                    if [ $? -eq 0 ]; then
                        echo "Compilation of verify.cpp successful."

                        # Run the verify executable with the public_key.bin, random_data.txt, and sign.bin files
                        VOUTPUT=$(./verify public_key.bin random_data.txt sign.bin)
                        echo $VOUTPUT

                        # Extract the execution cost from the output (assuming it's always formatted like "Execution Cost = 4.487 ms")
                        VEXECUTION_TIME=$(echo "$VOUTPUT" | grep -oP 'Execution Cost = \K[0-9.]+')

                        # Add the execution time to the total (converting ms to seconds for easier summation, optional)
                        TOTAL_EXECUTION_TIME=$(echo "$TOTAL_EXECUTION_TIME + $VEXECUTION_TIME" | bc)

                        # Check if the verify program ran successfully
                        if [ $? -eq 0 ]; then
                            echo "Verify program executed successfully."
                        else
                            echo "Error during verify program execution."
                        fi
                    else
                        echo "Compilation of verify.cpp failed."
                    fi
                else
                    echo "Error during sign program execution."
                fi
            else
                echo "Compilation of sign.cpp failed."
            fi
            echo "---------------------------------------------------------------------------------------------------"
        done
AVERAGE_EXECUTION_TIME=$(echo "$TOTAL_EXECUTION_TIME / $ITERATIONS" | bc -l)
echo "All $ITERATIONS iterations completed successfully."
echo "Total execution time: $TOTAL_EXECUTION_TIME ms"
echo "Average execution time: $AVERAGE_EXECUTION_TIME ms"