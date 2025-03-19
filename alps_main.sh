#!/bin/bash

# ------------------------------------------------------ #
#   Purpose: Main bash script to orchestrate Automatic Least-privilege Policy Suggestor (ALPS)
#
#   Author: Marcus Adair, University of Utah, Spring 2025
# ------------------------------------------------------ #

# MAke sure you are in the base dir of the CDK dir (TODO: edit to be better )
# ORRR TODO: take in the base dir of the CDK dir as an argument so you can run anywehre? 

PROJ_BASE_DIR=$1

THIS_DIR=$(pwd)

# TODO: make options for if there's no cdk.out from nested stacks? 
cd $PROJ_BASE_DIR
cd cdk.out || exit

# Name of file to create for combining CDK Stack JSON 
output_file="merged_output.json"


# Start the JSON file
echo "{" >> "$output_file"

# Combine all of indivudal JSON files for each stack
first=true
for file in *.json; do
    # Skip empty files
    if [ ! -s "$file" ] || [[ "$file" == "$output_file" ]]; then
        continue
    fi

    # Make sure the commas to seperate stacks are correct
    if [ "$first" = true ]; then
        first=false
    else
        echo "," >> "$output_file"
    fi

    # Append file content to the output
    echo "\"$file\": $(cat "$file")" >> "$output_file"
done

# End the JSON file
echo "}" >> "$output_file"

# Operate back in the base directory 
mv "$output_file" $THIS_DIR
cd $THIS_DIR




# TODO: check env or something and decide to use 'python' or 'python3'

# Extract the IAM Resources from the JSON 
echo "Parsing the output file ... "
IAM_POLICY_JSON=$(python3 extract_iam.py $output_file)

# TODO: handle the case where there is an empty dict returned --> Display message to user


# Parse the policies for insecurities 
rtrn_data=$(python3 insecurity_scan.py "$IAM_POLICY_JSON")
echo $rtrn_data



# TODO


