#!/bin/bash
# File to store the lab name
CLIENT_FILE=".client-name"
# Read the current value if the file exists
if [[ -f "$CLIENT_FILE" ]]; then
    DEFAULT_NAME=$(<"$CLIENT_FILE")
else
    DEFAULT_NAME=""
fi
# Prompt user with default (if any)
read -p "Enter FQDN or IP [${DEFAULT_NAME}]: " INPUT_NAME
# If the user entered nothing, keep the default
if [[ -z "$INPUT_NAME" ]]; then
    INPUT_NAME="$DEFAULT_NAME"
else
    # Save the new input for next time
    echo "$INPUT_NAME" > "$CLIENT_FILE"
fi
# Print what we’re using
echo "Using: client $INPUT_NAME"
CURRENT_DIR="$PWD"
#copy just the files we need
scp sgreen@$INPUT_NAME:/home/sgreen/remote-management-tsa/requirements.txt . 
scp sgreen@$INPUT_NAME:/home/sgreen/remote-management-tsa/mgmt-access.py sgreen@$INPUT_NAME:/home/sgreen/remote-management-tsa/mgmt-access.py .

