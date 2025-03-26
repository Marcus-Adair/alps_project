#!/usr/bin/env python3

import subprocess
import argparse
from config import BASE_DIR

# Set up argument parser
parser = argparse.ArgumentParser(description="Run the alps_main.sh script with optional flags.")
parser.add_argument("-v", "--verbose", action="store_true", help="Print full verboes output (with STDERR).")
parser.add_argument("-c", "--config", action="store_true", help="Sets directory to use for the base CDK directory. If not set, assumes that ALPS is in the base CDK directory and uses './'.")


# Parse arguments
args = parser.parse_args()

# Run the script
result = subprocess.run(["bash", "alps_main.sh", BASE_DIR], capture_output=True, text=True)


# Print STDERR only if verbose flag is set
if args.verbose:
    print("STDERR:\n", result.stderr)

# Print the output
print("STDOUT:\n", result.stdout)


