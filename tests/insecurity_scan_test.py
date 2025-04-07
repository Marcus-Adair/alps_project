'''

    Unit-Test Suite for ALPS.

    Tests files for the `insecurity_scan.py` file

'''
import pytest
from alps.insecurity_scan import create_suggested_python_code, check_overly_permissive, check_unnecessary_write_permissions


# Helper Method ------------------------------------------- #
# def get_iam_policy_template(policy_name, actions, actions_message_comment, resources, resources_message_comment, effect):
#     iam_policy_template = f'''
# Python Policy suggestion:
# -------------------------
# policy_var_name = iam.ManagedPolicy(self, "ADD_UNIQUE_STACK_IDENTIFIER_HERE",
#     managed_policy_name="{policy_name}",
#     description="ADD DESCRIPTION HERE",
#     statements=[
#         iam.PolicyStatement(
#             actions={str(actions)}, {actions_message_comment}
#             resources={str(resources)}, {resources_message_comment}
#             effect={effect}
#         )
#     ],
# )

# '''
#     return iam_policy_template



def get_set_raw_policy_template(action, effect, resouce):
    '''
        Helper method to retun JSON of IAM policy document
    '''
    raw_policy = {
        'Statement': 
            [
                {
                    'Action': action,
                    'Effect': effect,
                    'Resource': resouce
                }
            ],
        'Version': '2012-10-17'
        }
    return raw_policy

# -------------------------------------------------------- #


def test_not_none():
    '''
        Tests that check_overly_permissive() returns non-None values when passed an insecure policy
    '''
    
    name = "TestPolicyName"
    action = 'secretsmanager:GetSecretValue'
    effect = 'Allow'
    resource = 'arn:aws:secretsmanager::secret:*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, python_code_suggestions, found_suggestions = check_overly_permissive(name, raw_policy)

    assert (suggestions is not None) and (python_code_suggestions is not None) and (found_suggestions is not None)



def test_safe_policy_no_suggestions():
    '''
        Tests that no suggestions are found when check_overly_permissive() is passed a safe policy
    '''
    
    name = "TestPolicyName"
    action = 'secretsmanager:GetSecretValue'
    effect = 'Allow'
    resource = 'arn:aws:secretsmanager::secret:my-secret'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    assert not (found_suggestions)



def test_all_actions_found_suggestions():
    '''
        
    '''
    name = "TestPolicyName"
    action = '*'
    effect = 'Allow'
    resource = 'arn:aws:secretsmanager::secret:my-secret'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    assert found_suggestions 
    assert len(suggestions) > 0



def test_all_resources_found_suggestions():
    '''
        
    '''
    name = "TestPolicyName"
    action = 'secretsmanager:GetSecretValue'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    assert found_suggestions 
    assert len(suggestions) > 0




def test_all_actions_correct_warning():
    '''
        
    '''
    name = "TestPolicyName"
    action = "*"
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)


    expected_warning = f"[HIGHLY CRITICAL] {name}: The policy allows all actions ('*'), which is highly insecure."
    assert (expected_warning in suggestions)


def test_wildcard_resource_warning():
    name = "TestPolicyName"
    action = 's3:GetObject'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[CRITICAL] {name}: The policy allows all resources ('*'), which is highly insecure."
    assert found_suggestions
    assert expected in suggestions





def test_service_wide_action_s3_warning():
    name = "TestPolicyName"
    action = 's3:*'
    effect = 'Allow'
    resource = 'arn:aws:s3:::my-bucket'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected_warning = f"[WARNING] {name}: The action 's3:*' could be overly broad and may allow unintended actions on s3."
    assert found_suggestions
    assert expected_warning in suggestions





def test_wildcard_resource_warning():
    name = "TestPolicyName"
    action = 's3:GetObject'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[CRITICAL] {name}: The policy allows all resources ('*'), which is highly insecure."
    assert found_suggestions
    assert expected in suggestions




def test_sensitive_service_privilege_escalation_warning():
    name = "TestPolicyName"
    action = 'iam:*'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[HIGH RISK] {name}: The action 'iam:*' grants broad permissions on iam, which can lead to privilege escalation."
    assert found_suggestions
    assert expected in suggestions




def test_deny_statements_skipped():
    name = "TestPolicyName"
    action = '*'
    effect = 'Deny'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    assert not found_suggestions
    assert len(suggestions) == 0



def test_administrator_access_keyword():
    name = "TestPolicyName"
    action = 'AdministratorAccess'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[HIGHLY CRITICAL] {name}: The policy allows all actions ('AdministratorAccess'), which is highly insecure."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0




def test_empty_policy_no_suggestions():
    name = "EmptyPolicy"
    raw_policy = {
        "Version": "2012-10-17",
        "Statement": []
    }

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    assert not found_suggestions
    assert suggestions == set()



# TODO: add tests that code suggestions are right