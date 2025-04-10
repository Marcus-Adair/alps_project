#!/usr/bin/env python3

###########################################################
#
#   Wrapper script to run the main Bash script for orchestrating ALPS
#
#   This file hanldes arguments when 'alps' command is ran, calls alps_main.sh, and makes sure that paths to 
#   files are known. 
###########################################################

import sys
import os

# Add the directory containing this script to the sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to the directory where the main.py script is located
sys.path.append(SCRIPT_DIR)  # Add the script's directory to sys.path so other Python files can be imported

import subprocess
import argparse

ALPS_SCRIPT = os.path.join(SCRIPT_DIR, "alps_main.sh")  # Path to the alps_main.sh script

# -------------------------------------- #

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Run the alps_main.sh script with optional flags.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print full verboes output (with STDERR).")
    parser.add_argument("-c", "--config", type=str, help="Sets directory to use for the base CDK directory. If not set, assumes that ALPS is in the base CDK directory and uses './'.")

    # Parse arguments
    args = parser.parse_args()

    # Use the provided directory or default to './'
    BASE_DIR = args.config if args.config else './'  

    # Run the main ALPS script
    result = subprocess.run(["bash", ALPS_SCRIPT, BASE_DIR], capture_output=True, text=True)

    # Print STDERR only if verbose flag is set
    if args.verbose:
        print("STDERR:\n", result.stderr)

    # Print the output
    print(result.stdout)



if __name__ == "__main__":
    main()