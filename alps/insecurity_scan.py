# ------------------------------------------------------ #
#   Purpose: TODO
#
#   Author: Marcus Adair, University of Utah, Spring 2025
# ------------------------------------------------------ #

import json
import sys
import argparse
import re
############################################################



def create_suggested_python_code(policy_name, effect, actions, resources, actions_message="Tighten up the allowed actions here", resources_message="Use a specific resource here"):
    '''
        Converts an IAN policy document in JSON from to Python code for code suggestion
    '''


    # Form comment to add, with option of adding no comment with "" is input
    if actions_message == "":
        actions_message_comment = ""
    else:
        actions_message_comment = f"# {actions_message}"

    if resources_message == "":
        resources_message_comment = ""
    else:
        resources_message_comment = f"# {resources_message}"
    


    iam_policyStaments = f'''
Python Policy suggestion:
-------------------------
policy_var_name = iam.ManagedPolicy(self, "ADD_UNIQUE_STACK_IDENTIFIER_HERE",
    managed_policy_name="{policy_name}",
    description="ADD DESCRIPTION HERE",
    statements=[
        iam.PolicyStatement(
            actions={str(actions)}, {actions_message_comment}
            resources={str(resources)}, {resources_message_comment}
            effect={effect}
        )
    ],
)

'''
        
    return iam_policyStaments
        



def get_effect_actions_resources(policy_statement):
    '''
        Helper method to Parse a IAM policy Document 
    '''

    effect = policy_statement.get("Effect", "")

    actions = policy_statement.get("Action", [])
    actions = actions if isinstance(actions, list) else [actions]

    # Check for overly permissive resources
    resources = policy_statement.get("Resource", [])
    resources = resources if isinstance(resources, list) else [resources]

    return effect, actions, resources





def check_overly_permissive(policy_name, raw_policy_json):
    """
    Checks an IAM policy JSON for overly permissive statements, such as wildcards in actions and resources.
    
    """

    policy_statements = raw_policy_json.get("Statement", [])
    suggestions = set()
    python_code_suggestions = set()

    
    for statement in policy_statements:


        # Parse the Policy document
        effect, actions, resources = get_effect_actions_resources(statement)


        
        if effect != "Allow":
            continue  # Skip Deny statements

        # Check for overly permissive actions
        for action in actions:

            # Check for admin access (all actions allowed)
            if action == "*":
                suggestions.add(f"[HIGHLY CRITICAL] {policy_name}: The policy allows all actions ('*'), which is highly insecure.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources))

            elif 'AdministratorAccess' in action:
                suggestions.add(f"[HIGHLY CRITICAL] {policy_name}: The policy allows all actions ('AdministratorAccess'), which is highly insecure.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources))

            elif str(action).endswith("*"):
                service = action.split(":")[0]
                suggestions.add(f"[WARNING] {policy_name}: The action '{action}' could be overly broad and may allow unintended actions on {service}.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources))

        # Check for overly permissive resources
        for resource in resources:
            if resource == "*":
                suggestions.add(f"[CRITICAL] {policy_name}: The policy allows all resources ('*'), which is highly insecure.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources))

            elif str(resource).endswith("*"):
                suggestions.add(f"[WARNING] {policy_name}: The resource '{resource}' could be overly broad and may allow unintended access.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources))

        # Additional warnings for sensitive permissions
        sensitive_services = ["iam", "s3", "ec2", "lambda"]
        for action in actions:
            service = action.split(":")[0]
            if service in sensitive_services and (action.endswith("*") or action == "*"):
                suggestions.add(f"[HIGH RISK] {policy_name}: The action '{action}' grants broad permissions on {service}, which can lead to privilege escalation.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources))

    return suggestions, python_code_suggestions



def check_unnecessary_write_permissions(policy_name, raw_policy_json):
    """
    Checks an IAM policy JSON for unnecessary write permissions that could allow data tampering or destruction.

    """

    policy_statements = raw_policy_json.get("Statement", [])
    suggestions = set()
    python_code_suggestions = set()

    # Define high-risk write permissions
    high_risk_write_actions = {
        "s3": ["s3:DeleteObject", "s3:PutObject"],
        "ec2": ["ec2:TerminateInstances", "ec2:ModifyInstanceAttribute"],
        "iam": ["iam:DeleteUser", "iam:UpdateRole"],
        "lambda": ["lambda:DeleteFunction", "lambda:UpdateFunctionCode"]
    }

    for statement in policy_statements:
        # Parse the Policy document
        effect, actions, resources = get_effect_actions_resources(statement)

        if effect != "Allow":
            continue  # Skip Deny statements

        # Check for high-risk write actions
        for action in actions:
            service, operation = (action.split(":") + [""])[:2]  # Handle cases where action might not be well-formed
            if service in high_risk_write_actions and action in high_risk_write_actions[service]:
                suggestions.add(f"[WARNING] {policy_name}: The action '{action}' allows modification or deletion of resources.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources))

        # Check for wildcard write actions
        for service, risky_actions in high_risk_write_actions.items():
            for action in actions:
                if action.startswith(f"{service}:") and action.endswith("*"):
                    suggestions.add(f"[WARNING] {policy_name}: The action '{action}' grants potentially overly broad write permissions on {service}.")
                    python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources))

    return suggestions, python_code_suggestions


#### MAYBE: #######
# TODO: lack of conditions? 

# TODO:  Privilege Escalation Risks?
#   - "iam:CreatePolicyVersion" → Can update an IAM policy to grant more permissions.
#   - "iam:AttachUserPolicy" or "iam:AttachGroupPolicy" → Allows attaching policies


def scan_for_insecurities(json_policies_str):
    print(f'Starting scan for IAM insecurities ... ', file=sys.stderr)


    insecurities = set()
    python_suggestions = set()

    # TEMP DEBUG CODE 
    # display_count = 5
    # saw = 0

    try:
        json_policies = json.loads(json_policies_str)

        # For each stack
        for policies_in_a_sack in json_policies:

            # For each Policy
            for policy_name in json_policies[policies_in_a_sack]:

                # Get the Policy JSON
                raw_policy_document_json = json_policies[policies_in_a_sack][policy_name]


                # Parse for insecurites 

                # Check for overly permissive policies
                overly_permissive_warnings, overly_permissive_code_suggestions = check_overly_permissive(policy_name, raw_policy_document_json)
                insecurities.update(overly_permissive_warnings)
                python_suggestions.update(overly_permissive_code_suggestions)


                write_permissions_warnings, write_permissions_code_suggestions = check_unnecessary_write_permissions(policy_name, raw_policy_document_json)
                insecurities.update(write_permissions_warnings)
                python_suggestions.update(write_permissions_code_suggestions)


        return insecurities, python_suggestions

    except json.JSONDecodeError as e:

        return f"Error scanning for insecurities: {e}"

    

    


# MAIN 
if __name__ == "__main__":

    # Parse the argument
    parser = argparse.ArgumentParser(description='TODO')
    parser.add_argument('iam_policy_dict_str', type=str, help='Dict with IAM Policies')
    args = parser.parse_args()

    
    insecurities, code_suggestions = scan_for_insecurities(args.iam_policy_dict_str)


    # TODO: congreate insecurities + code_suggestion of the same policy name to format nice


    output = []
    for insecurity_i, code_suggestions_i in zip(insecurities, code_suggestions):
        output_i = f'''
{insecurity_i}
{code_suggestions_i}
'''
        output.append(output_i)



    # for insecur in insecurities:
    #     print(str(insecur), file=sys.stderr)
    #     print('\n', file=sys.stderr)
    # print('\n', file=sys.stderr)

    for output_i in output:
        print(str(output_i), file=sys.stderr)
        print('\n', file=sys.stderr)
    print('\n', file=sys.stderr)

    print(output)
