'''

    Unit-Test Suite for ALPS.

    Tests files for the `insecurity_scan.py` file

'''
import pytest
from alps.insecurity_scan import create_suggested_python_code, check_overly_permissive, check_unnecessary_write_permissions, check_iam_privilege_escalation



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


def test_wildcard_resource_warning_s3():
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


def test_service_wide_action_ec2_warning():
    name = "TestPolicyName"
    action = 'ec2:*'
    effect = 'Allow'
    resource = 'arn:aws:s3:::my-instance'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected_warning = f"[WARNING] {name}: The action 'ec2:*' could be overly broad and may allow unintended actions on ec2."
    assert found_suggestions
    assert expected_warning in suggestions



def test_wildcard_resource_warning_ec2():
    name = "TestPolicyName"
    action = 'ec2:*'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[CRITICAL] {name}: The policy allows all resources ('*'), which is highly insecure."
    assert found_suggestions
    assert expected in suggestions




def test_sensitive_service_privilege_escalation_warning_iam():
    name = "TestPolicyName"
    action = 'iam:*'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[HIGH RISK] {name}: The action 'iam:*' grants broad permissions on iam, which can lead to privilege escalation."
    assert found_suggestions
    assert expected in suggestions



def test_sensitive_service_privilege_escalation_warning_s3():
    name = "TestPolicyName"
    action = 's3:*'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[HIGH RISK] {name}: The action 's3:*' grants broad permissions on s3, which can lead to privilege escalation."
    assert found_suggestions
    assert expected in suggestions



def test_sensitive_service_privilege_escalation_warning_ec2():
    name = "TestPolicyName"
    action = 'ec2:*'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[HIGH RISK] {name}: The action 'ec2:*' grants broad permissions on ec2, which can lead to privilege escalation."
    assert found_suggestions
    assert expected in suggestions


def test_sensitive_service_privilege_escalation_warning_lambda():
    name = "TestPolicyName"
    action = 'lambda:*'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[HIGH RISK] {name}: The action 'lambda:*' grants broad permissions on lambda, which can lead to privilege escalation."
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




def test_empty_action_policy_no_suggestions():
    name = "EmptyPolicy",
    action = 'AdministratorAccess',
    effect = ''
    raw_policy = {
        "Version": "2012-10-17",
        "Statement": []
    }

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    assert not found_suggestions
    assert suggestions == set()






def test_overly_permissive_resources_s3():
    name = "TestPolicyName"
    action = 's3:PutObject'
    effect = 'Allow'
    resource = 'arn:aws:s3:::*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[WARNING] {name}: The resource '{resource}' could be overly broad and may allow unintended access."
    assert found_suggestions
    assert expected in suggestions



def test_overly_permissive_resources_s3_2():
    name = "TestPolicyName"
    action = 's3:PutObject'
    effect = 'Allow'
    resource = 'arn:aws:s3:::my-bucket/*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_overly_permissive(name, raw_policy)

    expected = f"[WARNING] {name}: The resource '{resource}' could be overly broad and may allow unintended access."
    assert found_suggestions
    assert expected in suggestions





#### Unneccessary write permissions  #################################################### 




def test_check_unnecessary_write_permissions_s3_delete():
    name = "TestPolicyName"
    action = 's3:DeleteObject'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_unnecessary_write_permissions(name, raw_policy)

    expected = f"[WARNING] {name}: The action '{action}' allows modification or deletion of resources."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0




def test_check_unnecessary_write_permissions_s3_put():
    name = "TestPolicyName"
    action = 's3:PutObject'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_unnecessary_write_permissions(name, raw_policy)

    expected = f"[WARNING] {name}: The action '{action}' allows modification or deletion of resources."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0




def test_check_unnecessary_write_permissions_ec2_terminate_instance():
    name = "TestPolicyName"
    action = 'ec2:TerminateInstances'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_unnecessary_write_permissions(name, raw_policy)

    expected = f"[WARNING] {name}: The action '{action}' allows modification or deletion of resources."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0



def test_check_unnecessary_write_permissions_ec2_modify_instance():
    name = "TestPolicyName"
    action = 'ec2:ModifyInstanceAttribute'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_unnecessary_write_permissions(name, raw_policy)

    expected = f"[WARNING] {name}: The action '{action}' allows modification or deletion of resources."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0



def test_check_unnecessary_write_permissions_iam_delete_user():
    name = "TestPolicyName"
    action = 'iam:DeleteUser'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_unnecessary_write_permissions(name, raw_policy)

    expected = f"[WARNING] {name}: The action '{action}' allows modification or deletion of resources."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0


def test_check_unnecessary_write_permissions_iam_update_role():
    name = "TestPolicyName"
    action = 'iam:UpdateRole'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_unnecessary_write_permissions(name, raw_policy)

    expected = f"[WARNING] {name}: The action '{action}' allows modification or deletion of resources."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0



def test_check_unnecessary_write_permissions_lambda_delete_fx():
    name = "TestPolicyName"
    action = 'lambda:DeleteFunction'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_unnecessary_write_permissions(name, raw_policy)

    expected = f"[WARNING] {name}: The action '{action}' allows modification or deletion of resources."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0


def test_check_unnecessary_write_permissions_lambda_update_fx_code():
    name = "TestPolicyName"
    action = 'lambda:UpdateFunctionCode'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_unnecessary_write_permissions(name, raw_policy)

    expected = f"[WARNING] {name}: The action '{action}' allows modification or deletion of resources."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0





#### Privilege Escalation Risks  #################################################### 


def test_check_privilige_escalation_PutUserPolicy():
    name = "TestPolicyName"
    action = 'iam:PutUserPolicy'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_iam_privilege_escalation(name, raw_policy)

    expected = f"[HIGH RISK] {name}: The action '{action}' could allow users or roles to escalate their privileges, potentially granting themselves full administrative access."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0



def test_check_privilige_escalation_PutGroupPolicy():
    name = "TestPolicyName"
    action = 'iam:PutGroupPolicy'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_iam_privilege_escalation(name, raw_policy)

    expected = f"[HIGH RISK] {name}: The action '{action}' could allow users or roles to escalate their privileges, potentially granting themselves full administrative access."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0



def test_check_privilige_escalation_CreatePolicy():
    name = "TestPolicyName"
    action = 'iam:CreatePolicy'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_iam_privilege_escalation(name, raw_policy)

    expected = f"[HIGH RISK] {name}: The action '{action}' could allow users or roles to escalate their privileges, potentially granting themselves full administrative access."
    assert found_suggestions
    assert expected in suggestions
    assert len(suggestions) > 0



def test_not_none_privilege_escalation():
    '''
        Tests that check_overly_permissive() returns non-None values when passed an insecure policy
    '''
    name = "TestPolicyName"
    action = 'iam:CreatePolicy'
    effect = 'Allow'
    resource = '*'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, python_code_suggestions, found_suggestions = check_iam_privilege_escalation(name, raw_policy)

    assert (suggestions is not None) and (python_code_suggestions is not None) and (found_suggestions is not None)



def test_safe_policy_no_suggestions_privilege_escalation():    
    name = "TestPolicyName"
    action = 'secretsmanager:GetSecretValue'
    effect = 'Allow'
    resource = 'arn:aws:secretsmanager::secret:my-secret'

    raw_policy = get_set_raw_policy_template(action, effect, resource)

    suggestions, _, found_suggestions = check_iam_privilege_escalation(name, raw_policy)

    assert not (found_suggestions)


############################################################################################ 



def test_python_code_suggestion_default_output():

    code_suggestions_result = create_suggested_python_code(
        policy_name="MyPolicy",
        effect="iam.Effect.ALLOW",
        actions=["s3:GetObject"],
        resources=["arn:aws:s3:::my-bucket/*"]
    )

    assert 'managed_policy_name="MyPolicy"' in code_suggestions_result
    assert "actions=['s3:GetObject']" in code_suggestions_result
    assert "resources=['arn:aws:s3:::my-bucket/*']" in code_suggestions_result
    assert "# Tighten up the allowed actions here" in code_suggestions_result

    # Test that default comments are used
    assert "# Use a specific resource here" in code_suggestions_result
    assert "effect=iam.Effect.ALLOW" in code_suggestions_result



def test_python_code_suggestion_empty_comments():

    code_suggestions_result = create_suggested_python_code(
        policy_name="MyPolicy",
        effect="iam.Effect.ALLOW",
        actions=["s3:GetObject"],
        resources=["arn:aws:s3:::my-bucket/*"],
        actions_message="",
        resources_message=""
    )

    assert 'managed_policy_name="MyPolicy"' in code_suggestions_result
    assert "actions=['s3:GetObject']" in code_suggestions_result
    assert "resources=['arn:aws:s3:::my-bucket/*']" in code_suggestions_result

    # Test that the default comment-suggestions aren't added when method's manually passed empty messages
    assert "# Tighten up the allowed actions here" not in code_suggestions_result
    assert "# Use a specific resource here" not in code_suggestions_result



def test_python_code_suggestion_custom_comments():
    code_suggestions_result = create_suggested_python_code(
        policy_name="MyPolicy",
        effect="iam.Effect.ALLOW",
        actions=["lambda:InvokeFunction"],
        resources=["arn:aws:lambda:::function:*"],
        actions_message="Only allow specific functions",
        resources_message="Avoid wildcards"
    )

    assert "# Only allow specific functions" in code_suggestions_result
    assert "# Avoid wildcards" in code_suggestions_result


def test_python_code_suggestion_empty_policy_name():

    with pytest.raises(ValueError) as excinfo:
        create_suggested_python_code(
            policy_name="",
            effect="iam.Effect.ALLOW",
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::my-bucket/*"],
        )
    assert str(excinfo.value) == "The 'policy_name' parameter must not be empty or None."


def test_python_code_suggestion_empty_effect():

    with pytest.raises(ValueError) as excinfo:
        create_suggested_python_code(
            policy_name="MyPolicy",
            effect="",
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::my-bucket/*"],
        )
    assert str(excinfo.value) == "The 'effect' parameter must not be empty or None."


def test_python_code_suggestion_empty_actions():

    with pytest.raises(ValueError) as excinfo:
        create_suggested_python_code(
            policy_name="MyPolicy",
            effect="iam.Effect.ALLOW",
            actions=[],
            resources=["arn:aws:s3:::my-bucket/*"],
        )
    assert str(excinfo.value) == "The 'actions' parameter must not be empty or None."


def test_python_code_suggestion_empty_resources():

    with pytest.raises(ValueError) as excinfo:
        create_suggested_python_code(
            policy_name="MyPolicy",
            effect="iam.Effect.ALLOW",
            actions=["s3:GetObject"],
            resources=[],
        )
    assert str(excinfo.value) == "The 'resources' parameter must not be empty or None."


    
######################################################################


# TODO: add tests to checks for proper error returns 

# TODO: add tests that code suggestions are right