# ------------------------------------------------------ #
#   Purpose: TODO
#
#   Author: Marcus Adair, University of Utah, Spring 2025
# ------------------------------------------------------ #

import json
import sys
import argparse
############################################################



def json_to_cdk(json_policy):
    '''
    
        Converts an IAN policy document in JSON from to Python code for code suggestion
    '''
    policy_dict = json.loads(json_policy)
    iam_policyStaments = []
    
    for statement in policy_dict["Statement"]:
        effect = "iam.Effect.ALLOW" if statement["Effect"] == "Allow" else "iam.Effect.DENY"
        actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        resources = statement["Resource"] if isinstance(statement["Resource"], list) else [statement["Resource"]]
        
        # Append Python code
        iam_policyStaments.append(f"iam.PolicyStatement(effect={effect}, actions={actions}, resources={resources})")
        
    return iam_policyStaments
        



# TODO: Make function for: Overly Permissive Actions
#   - "Action": "*" → Grants all actions, which is very dangerous.
#   - "Action": ["s3:*", "ec2:*"] → Full access to specific services. Look for excessive permissions that aren't needed.



# TODO: Make function for: Overly Broad Resources
#   - "Resource": "*" → Grants access to all resources in the AWS account.
#   - "Resource": "arn:aws:s3:::my-bucket/*" → If this isn’t intended, it could allow unintended access to sensitive data.



# TODO: Make function for: Allowing All Principals in Resource Policies
#   - "Principal": "*" → This allows anyone to assume the role (in Trust policies), which is dangerous. 
#   - Look for other cases with this principal 



# TODO: Make function for: Unnecessary Write Permissions
#   - "Action": ["s3:DeleteObject", "s3:PutObject"] → This could allow data tampering or destruction.


# TODO: Make function for: Check For Admin Access
#   - "AdministratorAccess" or "Action": "*" without restrictions is dangerous.






#### MAYBE: #######
# TODO: lack of conditions? 

# TODO:  Privilege Escalation Risks?
#   - "iam:CreatePolicyVersion" → Can update an IAM policy to grant more permissions.
#   - "iam:AttachUserPolicy" or "iam:AttachGroupPolicy" → Allows attaching policies


def scan_for_insecurities(json_policies_str):
    print(f'Starting scan for IAM insecurities ... ', file=sys.stderr)


    insecurities = [] # TODO: append to this when securities are noticed 

    # TEMP DEBUG CODE 
    display_count = 5
    saw = 0

    try:
        json_policies = json.loads(json_policies_str)


        for stack_policies in json_policies:
            for policy_name in json_policies[stack_policies]:

                raw_policy_document_json = json_policies[stack_policies][policy_name]
                policy_statements = raw_policy_document_json['Statement']
                # TODO: for each policy_statement in policy_statements: parse them 

                # print(str(raw_policy_document_json) + "\n", file=sys.stderr)


                # TODO: finish crafting policy 
                # policy = {
                #     "name": policy_name,
                #     "statement": raw_policy_document_json['Statement']

                # }
                # print(str(policy) + "\n", file=sys.stderr)


                # python_pol = json_to_cdk(json.dumps(raw_policy_document_json))
                # print(str(python_pol), file=sys.stderr)
                # print("\n", file=sys.stderr)




                # TEMP DEBUG CODE 
                saw += 1
                if saw == display_count:
                    return insecurities


            print('----------------------------------- \n', file=sys.stderr)





        #return(str(json_policies_str))
        return insecurities




    except json.JSONDecodeError as e:

        return f"Error scanning for insecurities: {e}"

    

    


# MAIN 
if __name__ == "__main__":

    # Parse the argument
    parser = argparse.ArgumentParser(description='TODO')
    parser.add_argument('iam_policy_dict_str', type=str, help='Dict with IAM Policies')
    args = parser.parse_args()

    
    insecurities = scan_for_insecurities(args.iam_policy_dict_str)
    print(insecurities)
