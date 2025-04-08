#!/bin/bash

# ------------------------------------------------------ #
#   Purpose: Main bash script to orchestrate Automatic Least-privilege Policy Suggestor (ALPS)
#
#   Author: Marcus Adair, University of Utah, Spring 2025
# ------------------------------------------------------ #

# Set the ALPS directory to the directory of the script
ALPS_DIR="$(dirname "$(realpath "$0")")"

PROJ_BASE_DIR=$1 # base dir 


# Check what Pythnon to use 
if command -v python3 &>/dev/null; then
    PYTHON_CMD=python3
elif command -v python &>/dev/null; then
    PYTHON_CMD=python
else
    echo "Error: No Python interpreter found!" >&2
    exit 1
fi


# Go into the project base dir and look for cdk.out to parse
cd $PROJ_BASE_DIR
if [ ! -d "cdk.out" ]; then
    echo "Error: cdk.out directory does not exist. Make sure you're in the base dir of your CDK project or use the --config flag."
    exit 1
fi
cd cdk.out || exit

# Name of temp file to create for combining CDK Stack JSON 
OUTPUT_FILE="merged_output.json"

# Start the JSON file
echo "{" >> "$OUTPUT_FILE"

# Combine all of indivudal JSON files for each stack
FIRST=true
for file in *.json; do
    # Skip empty files
    if [ ! -s "$file" ] || [[ "$file" == "$OUTPUT_FILE" ]]; then
        continue
    fi

    # Make sure the commas to seperate stacks are correct
    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        echo "," >> "$OUTPUT_FILE"
    fi

    # Append file content to the output
    echo "\"$file\": $(cat "$file")" >> "$OUTPUT_FILE"
done

# End the JSON file
echo "}" >> "$OUTPUT_FILE"

# Operate back in the base directory 
mv "$OUTPUT_FILE" $ALPS_DIR
cd $ALPS_DIR


# Extract the IAM Resources from the JSON 
echo "Parsing the output file ... "
IAM_POLICY_JSON=$($PYTHON_CMD extract_iam.py $OUTPUT_FILE)


# TODO: handle the case where there is an empty dict returned --> Display message to user


# Parse the policies for insecurities 
RTRN_DATA=$($PYTHON_CMD insecurity_scan.py "$IAM_POLICY_JSON")


# Print the final output
echo "$RTRN_DATA" | jq -r '.[]' | while IFS= read -r item; do
    echo "$item"
done



# Clean up temp file 
rm $OUTPUT_FILE



