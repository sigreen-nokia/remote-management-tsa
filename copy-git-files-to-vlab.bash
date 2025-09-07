#!/bin/bash
# File to store the lab name
LAB_FILE=".lab-name"
# Read the current value if the file exists
if [[ -f "$LAB_FILE" ]]; then
    DEFAULT_NAME=$(<"$LAB_FILE")
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
    echo "$INPUT_NAME" > "$LAB_FILE"
fi
# Print what we’re using
echo "Using: VLAB $INPUT_NAME"
CURRENT_DIR="$PWD"
#copy just the files we need
scp ./requirements.txt support@$INPUT_NAME:/home/support/remote-management-tsa/
scp ./mgmt-access.py support@$INPUT_NAME:/home/support/remote-management-tsa/

