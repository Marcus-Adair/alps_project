# Automatic Least-Privilege Policy Suggestor (ALPS)

This repository contains code for **Automatic Least-Privilege Policy Suggestor (ALPS)**—my Spring 2025 **Software & Systems Security Project**.

## Overview

ALPS is an **AWS IAM least-privilege policy suggestor/generator** for **AWS Cloud Workflows**. It is designed for integration with the [AWS Cloud Development Kit (CDK)](https://aws.amazon.com/cdk/).

At a high level, ALPS:

- Parses synthesized **Python CDK** code

- Identifies **insecure IAM policies**

- Suggests **more secure IAM policies** in the form of:
  - **Python CDK code**
  - **Descriptive security recommendations**

## Installation

🚧 **TODO:** Add instructions for installing ALPS.

## Usage

- After installation, navigate to the base directory of your CDK project and run ALPS using the following command:  
  `alps_project`

- To view all available options for running ALPS, use the command:  
  `alps_project -h`

- To run ALPS from any location and specify the base directory of your CDK project, use the following command:  
  `alps_project -c <base_dir>`  
  where `<base_dir>` is the path to your CDK project.

- To execute ALPS in verbose mode and display additional information, use:  
  `alps_project -v`

## Additional Notes:

- ALPS assumes that user policies are named and do not contain "DefaultPolicy". If "DefaultPolicy" is contained in a manually created policy then ALPS will ignore it.
