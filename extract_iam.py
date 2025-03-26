# ------------------------------------------------------ #
#   Purpose: Helper python code for parsing a JSON file that contains JSON that defines AWS services
#            This file creates a dictionary that maps Nested Stack names to Policies and the Policy code
#            so that the Policies can be easily scanned for insecurities.
#
#   Author: Marcus Adair, University of Utah, Spring 2025
# ------------------------------------------------------ #

import json
import sys
import argparse
############################################################


def extract_iam_resources(file_path):
    '''
        Parses a JSON file to extract IAM resources. This assumes input file path contains a dict of 
        multiple different Nested Stacks and the JSON that defines the stacks' AWS services

        This returns a dict where keys are Stack names and valus are lists of AWS:IAM resources defined in JSON
    
        file_path (string): path to the file containing Cloud infrastructre JSON output from 'cdk synth' 
    '''

    # The types of IAM resources to extract
    desired_resource_types = ["AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"] # "AWS::IAM::Role", ""AWS::S3::BucketPolicy""

    # Open the file as JSON
    with open(file_path, 'r') as file:
        json_data = json.load(file)

    # Init return dict
    iam_resources = {}

    # For each nested stack
    for stack in json_data: 

        stack_iam = [] # init list for saving IAM resources

        # Extract the AwS::IAM resources 
        for stack_key in json_data[stack]:
            if stack_key == 'Resources':
                for resource in json_data[stack][stack_key]:
                    for resource_item in json_data[stack][stack_key][resource]:
                        if resource_item == "Type":
                            if json_data[stack][stack_key][resource][resource_item] in desired_resource_types:
                                
                                # Save the IAM resource
                                stack_iam.append(json_data[stack][stack_key][resource])

        # Only save data when the stack has IAM resources
        if len(stack_iam) > 0:
            iam_resources[stack] = stack_iam

    return iam_resources



def get_stacks_policies(file_path):
    '''
        Parses a JSON file to extract IAM resources. This assumes input file path contains a dict of 
        multiple different Nested Stacks and the JSON that defines the stacks' AWS services. This further
        process extracted IAM resources to parse out the IAM Policy Names and the Code that defines the policies
        to easily scan them for insecure policy code.

        Returns a dict of dicts ... TODO: explain the return format 


        file_path (string): path to the file containing Cloud infrastructre JSON output from 'cdk synth' 
    '''

    try:

        # Extract the IAM Resources
        iam_resources = extract_iam_resources(file_path)

        print(f"\nExtracting IAM Resources from {len(iam_resources)} JSON files:\n", file=sys.stderr)


        stack_policies_dict = {}
        policy_count = 0 

        # For each stack (with saved resources), extract the policy names/code
        for stack_name, stack_resources in iam_resources.items():
            print('----------------------------', file=sys.stderr)
            print(f"Parsing IAM Resources from Stack: {stack_name}", file=sys.stderr)

            # Dict of policy names and their documents
            stack_policies = {}

            policy_name_count = 0
            policy_document_count = 0

            # Go through each saved resource in a stack 
            for stack_resource in stack_resources:
                for stack_data in stack_resource:
                    if stack_data == 'Properties':

                        # init vars
                        policy_name = None
                        policy_document = None


                        # Parse out the Policy name
                        if 'PolicyName' in stack_resource[stack_data]:
                            policy_name = stack_resource[stack_data]['PolicyName']
                            policy_name_count += 1
                            # print('Policy Name: ' + policy_name, file=sys.stderr)

                        if 'ManagedPolicyName' in stack_resource[stack_data]:
                            policy_name = stack_resource[stack_data]['ManagedPolicyName']
                            policy_name_count += 1
                            # print('ManagedPolicy Name: ' + policy_name, file=sys.stderr)


                        # Parse out the Policy code 
                        if 'PolicyDocument' in stack_resource[stack_data]:
                            policy_document = stack_resource[stack_data]['PolicyDocument']
                            policy_document_count += 1
                            # print('Policy Document: ' + str(policy_document), file=sys.stderr)

                        # Save the policy 
                        if policy_name and policy_document:
                            
                            if not ("DefaultPolicy" in policy_name): # Ignore automatically created default policies      

                                # print(f'Found Policy {policy_name}\n', file=sys.stderr)
                                stack_policies[policy_name] = policy_document
                                policy_count += 1


            # Save list of policies to the stack name in the dict to return 
            stack_policies_dict[stack_name] = stack_policies


    ################################################## Debug Print statements ####################
            # # PRINT STACK POLICY INFO 
            # print(f"Stack: {stack_name}", file=sys.stderr)
            # print(f"policy name count: {policy_name_count}", file=sys.stderr)
            # print(f"policy document count: {policy_document_count}", file=sys.stderr)
            # print('\n')

            # print('----------------------------', file=sys.stderr)
            # print("\n", file=sys.stderr)


        # # PRINT THE STACK POLICIES 
        # print(f"Stacks and their Policies:", file=sys.stderr)    
        # for stack_pol in stack_policies_dict:
        #     print(f"a stack pol: ", file=sys.stderr)
        #     print(str(stack_policies_dict[stack_pol]), file=sys.stderr)
        #     print('\n', file=sys.stderr)
    ###############################################################################################
        
        print(f'Found Policy {str(policy_count)} policies.', file=sys.stderr)


        # Return stack_policies_dict as JSON to the calling bash script
        return json.dumps(stack_policies_dict)

    except json.JSONDecodeError as e:
        return f"Error getting stack policies: {e}"

# MAIN 
if __name__ == "__main__":

    # Parse the argument
    parser = argparse.ArgumentParser(description='Navigate given dir to parse for IAM policies')
    parser.add_argument('file_path', type=str, help='Path to the JSON file with CDK stack info')
    args = parser.parse_args()

    # Get the stack policies
    stack_policies = get_stacks_policies(args.file_path)
    print(stack_policies)
