# ------------------------------------------------------ #
#   Purpose: TODO
#
#   Author: Marcus Adair, University of Utah, Spring 2025
# ------------------------------------------------------ #

import json
import sys
import argparse
############################################################




##############################################################################################################
# General Helper Methods                                                                                     # 
##############################################################################################################


def print_v(verbose_log):
    '''
        Prints something to sys.stderr so it appears in verbose logging
    '''
    print(verbose_log, file=sys.stderr)

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
        

def merge_policy_strings(policy_sugg_1, policy_sugg_2):
    '''
        Merges ... TODO: 
    '''
    lines1 = policy_sugg_1.strip().splitlines()
    lines2 = policy_sugg_2.strip().splitlines()
    merged_lines = []

    for l1, l2 in zip(lines1, lines2):

        if l1 == l2:
            merged_lines.append(l1)
        elif len(l1) > len(l2):
            merged_lines.append(l1)
        else: merged_lines.append(l2)
        
    return "\n".join(merged_lines)



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





##############################################################################################################
# Helper methods to scan for specific insecurities                                                           # 
##############################################################################################################



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
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources, actions_message="Specify certain actions here", resources_message=""))

            elif 'AdministratorAccess' in action:
                suggestions.add(f"[HIGHLY CRITICAL] {policy_name}: The policy allows all actions ('AdministratorAccess'), which is highly insecure.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources, actions_message="Giving AdministratorAccess here is dangerous", resources_message=""))

            # Check if all actions allowed for a specific service
            elif str(action).endswith("*"):
                service = action.split(":")[0]
                suggestions.add(f"[WARNING] {policy_name}: The action '{action}' could be overly broad and may allow unintended actions on {service}.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources, actions_message="Consider tightening the allowed actions to make things more least-privilege", resources_message=""))

        # Check for overly permissive resources
        for resource in resources:
            # All resources allowed
            if resource == "*":
                suggestions.add(f"[CRITICAL] {policy_name}: The policy allows all resources ('*'), which is highly insecure.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources, actions_message="", resources_message="Specify certain resources here"))


            elif str(resource).endswith("*"):
                suggestions.add(f"[WARNING] {policy_name}: The resource '{resource}' could be overly broad and may allow unintended access.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resource, actions_message="", resources_message="Consider tightening up the allowed resources here"))



        # Additional warnings for sensitive permissions
        sensitive_services = ["iam", "s3", "ec2", "lambda"]
        for action in actions:
            service = action.split(":")[0]
            if service in sensitive_services and (action.endswith("*") or action == "*"):
                suggestions.add(f"[HIGH RISK] {policy_name}: The action '{action}' grants broad permissions on {service}, which can lead to privilege escalation.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources, actions_message="Consider tightening the allowed actions to make things more least-privilege", resources_message=""))


    found_suggestions =  len(suggestions) != 0 

    return suggestions, python_code_suggestions, found_suggestions



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

    # TODO: add more specific code suggestion messages here

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
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources,  actions_message="Consider if these actions are needed or could be tightened", resources_message=""))

        # Check for wildcard write actions
        for service, risky_actions in high_risk_write_actions.items():
            for action in actions:
                if action.startswith(f"{service}:") and action.endswith("*"):
                    suggestions.add(f"[WARNING] {policy_name}: The action '{action}' grants potentially overly broad write permissions on {service}.")
                    python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources, actions_message="Consider if these actions are needed or could be tightened", resources_message=""))


    # Flag if found suggestions
    found_suggestions =  len(suggestions) != 0

    return suggestions, python_code_suggestions, found_suggestions



def check_iam_privilege_escalation(policy_name, raw_policy_json):
    """
    Checks an IAM policy JSON for unnecessary write permissions that could allow data tampering or destruction.

    """

    policy_statements = raw_policy_json.get("Statement", [])
    suggestions = set()
    python_code_suggestions = set()

    # Define high-risk write IAM actions 
    high_risk_iam_actions = ["iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy", "iam:AttachUserPolicy",
                "iam:AttachGroupPolicy", "iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:CreatePolicy",
                "iam:CreateRole", "iam:PassRole", "iam:UpdateAssumeRolePolicy",
                "iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"]


    for statement in policy_statements:
        # Parse the Policy document
        effect, actions, resources = get_effect_actions_resources(statement)

        if effect != "Allow":
            continue  # Skip Deny statements

        # Check for high-risk iam actions
        for action in actions:
            if action in high_risk_iam_actions:
                suggestions.add(f"[HIGH RISK] {policy_name}: The action '{action}' could allow users or roles to escalate their privileges, potentially granting themselves full administrative access.")
                python_code_suggestions.add(create_suggested_python_code(policy_name, effect, actions, resources,  actions_message="Review the action(s) here and consider restricting/removing them.", resources_message=""))


    # Flag if found suggestions
    found_suggestions =  len(suggestions) != 0

    return suggestions, python_code_suggestions, found_suggestions




#### MAYBE: #######
# TODO: lack of conditions? 


# -------------------------------------------------------------------------- #
# Main method to scan for policy insecurities
# -------------------------------------------------------------------------- #


def scan_for_insecurities(json_policies_str):
    print_v(f'Starting scan for IAM insecurities ... ')


    insecurities = set()
    python_suggestions = set()
    insecure_policy_names = set()


    try:
        json_policies = json.loads(json_policies_str)

        # For each stack
        for policies_in_a_sack in json_policies:

            # For each Policy
            for policy_name in json_policies[policies_in_a_sack]:

                # Note if security suggestions are found for the polciy
                found_suggestions = False

                # Get the Policy JSON
                raw_policy_document_json = json_policies[policies_in_a_sack][policy_name]


                # Parse for insecurites 
                # -------------------------- #
                # Check for overly permissive policies
                overly_permissive_warnings, overly_permissive_code_suggestions, found_overly_permissive_suggestions = check_overly_permissive(policy_name, raw_policy_document_json)
                insecurities.update(overly_permissive_warnings)
                python_suggestions.update(overly_permissive_code_suggestions)


                write_permissions_warnings, write_permissions_code_suggestions, found_write_permissions_suggestions = check_unnecessary_write_permissions(policy_name, raw_policy_document_json)
                insecurities.update(write_permissions_warnings)
                python_suggestions.update(write_permissions_code_suggestions)


                iam_privilege_escalation_warnings, iam_privilege_escalation_code_suggestions, found_iam_privilege_escalation_suggestions = check_iam_privilege_escalation(policy_name, raw_policy_document_json)
                insecurities.update(iam_privilege_escalation_warnings)
                python_suggestions.update(iam_privilege_escalation_code_suggestions)

                # Track unique policy names with security vulnerabilites
                found_suggestions = found_overly_permissive_suggestions or found_iam_privilege_escalation_suggestions or found_iam_privilege_escalation_suggestions
                if found_suggestions:
                    insecure_policy_names.add(policy_name)


        return insecurities, python_suggestions, insecure_policy_names

    except json.JSONDecodeError as e:

        return f"Error scanning for insecurities: {e}"

    

    


# MAIN 
if __name__ == "__main__":

    # Parse the argument
    parser = argparse.ArgumentParser(description='TODO')
    parser.add_argument('iam_policy_dict_str', type=str, help='Dict with IAM Policies')
    args = parser.parse_args()

    
    insecurities, code_suggestions, insecure_policy_names = scan_for_insecurities(args.iam_policy_dict_str)

    insecurities_map = {}
    code_suggestions_map = {}

    # Aggregate insecurities  of the same policy name to format nice
    for policy_name in insecure_policy_names:

        # Merge security warnings for the same policy

        # Find warnings for the same iam policy
        insecurities_with_name = []
        for insecurity in insecurities:
            if policy_name in insecurity:                
                insecurities_with_name.append(insecurity)

        if len(insecurities_with_name)  > 1:

            merged_insecurity_warning = ""
            for insecur in insecurities_with_name:
                insecurities.remove(insecur) # Remove single warning
                merged_insecurity_warning += f"{insecur}\n" # Merge/append warning

            insecurities.add(merged_insecurity_warning)
            insecurities_map[policy_name] = merged_insecurity_warning

        else:
            insecurities_map[policy_name] = insecurities_with_name[0]

        # ------------------------------------------------------------------------------------------------ #

        # TODO: Aggregate code suggestions too!!!!!! (when i start doing more custom code suggetsions, they'll be to be formated)
        code_suggestions_with_name = []
        for code_suggestion in code_suggestions:
            if policy_name in code_suggestion:
                code_suggestions_with_name.append(code_suggestion)


        # Remove
        if len(code_suggestions_with_name)  > 1:

            merged_code_suggestion = code_suggestions_with_name[0]
            first_sugg = True

            for code_sugg in code_suggestions_with_name:
                
                code_suggestions.remove(code_sugg) # Take out unmerged code suggestion
                if first_sugg:
                    first_sugg = False
                    continue
                
                merged_code_suggestion = merge_policy_strings(merged_code_suggestion, code_sugg)

            code_suggestions.add(merged_code_suggestion)
            code_suggestions_map[policy_name] = merged_code_suggestion

        else:
            code_suggestions_map[policy_name] = code_suggestions_with_name[0]
         # ------------------------------------------------------------------------------------------------ #

    # Return suggestions to be printed 
    output = []
    for policy_name in insecure_policy_names:
        insecurity_i = insecurities_map[policy_name]
        code_suggestions_i = code_suggestions_map[policy_name]


    
        output_i = f'''
{insecurity_i}
{code_suggestions_i}
\n
'''
        output.append(output_i)


    # Return output to main bash script 
    print(json.dumps(output))

