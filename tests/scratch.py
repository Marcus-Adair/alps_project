from alps.insecurity_scan import create_suggested_python_code, check_overly_permissive, check_unnecessary_write_permissions


def get_set_raw_policy_template(actions, effect, resouce):
    '''
        Helper method to retun JSON of IAM policy document
    '''
    raw_policy = {
        'Statement': 
            [
                {
                    'Action':actions,
                    'Effect': effect,
                    'Resource': resouce
                }
            ],
        'Version': '2012-10-17'
        }
    return raw_policy

# -------------------------------------------------------- #



name = "TestPolicyName"
action = '*'
effect = 'Allow'
resource = 'arn:aws:secretsmanager::secret:test-secretname'

raw_policy = get_set_raw_policy_template(action, effect, resource)


suggestions, python_code_suggestions, found_suggestions = check_overly_permissive(name, raw_policy)



print(suggestions, python_code_suggestions, found_suggestions)