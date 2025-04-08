'''

    Unit-Test Suite for ALPS.

    Tests files for the `extract_iam.py` file

'''
import pytest
import json
from alps.extract_iam import get_stacks_policies, extract_iam_resources
from unittest.mock import mock_open, patch

# Sample input mimicking a CDK output JSON file with IAM policies
mock_json_input_1 = {
    "NestedStack1": {
        "Resources": {
            "Policy1": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "MyTestPolicy",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "s3:ListBucket",
                            "Resource": "*"
                        }]
                    }
                }
            },
            "SomeOtherResource": {
                "Type": "AWS::S3::Bucket"
            }
        }
    },
    "NestedStack2": {
        "Resources": {
            "ManagedPolicy1": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": "MyManagedPolicy",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Deny",
                            "Action": "ec2:*",
                            "Resource": "*"
                        }]
                    }
                }
            }
        }
    }
}

mock_json_input_2 = {
  "NestedStack1": {
    "Resources": {
      "Policy1": {
        "Type": "AWS::S3::BucketPolicy",
        "Properties": {
          "PolicyName": "MyTestPolicy",
          "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "*"
              }
            ]
          }
        }
      },
      "SomeOtherResource": {
        "Type": "AWS::S3::Bucket"
      }
    }
  }
}



mock_json_input_empy = {
}



mock_json_str_1 = json.dumps(mock_json_input_1)
mock_json_str_2 = json.dumps(mock_json_input_2)
mock_json_str_empty = json.dumps(mock_json_input_empy)


##### extract_iam_resources() Tests ##########################################



@patch("builtins.open", new_callable=mock_open, read_data=mock_json_str_empty)
def test_extract_iam_resources_empty_stack(mock_file):
    result = extract_iam_resources("fake/path.json")

    assert isinstance(result, dict)
    assert result == {}



@patch("builtins.open", new_callable=mock_open, read_data='{"invalid": "json"')
def test_extract_iam_resources_json_error(mock_file):
    result = extract_iam_resources("fake/path.json")
    assert result.startswith("Error extracting iam resources")




@patch("builtins.open", new_callable=mock_open, read_data='')
def test_extract_iam_resources_empty_string(mock_file):
    result = extract_iam_resources("fake/path.json")
    assert result.startswith("Error extracting iam resources")



@patch("builtins.open", new_callable=mock_open, read_data='{"irrelevant": "json"}')
def test_extract_iam_resources_irrelevant_json(mock_file):
    
    result = extract_iam_resources("fake/path.json")
    assert isinstance(result, dict)
    assert result == {}


@patch("builtins.open", new_callable=mock_open, read_data=mock_json_str_1)
def test_extract_iam_resources(mock_file):
    result = extract_iam_resources("fake/path.json")

    assert "NestedStack1" in result
    assert "NestedStack2" in result

    assert len(result["NestedStack1"]) == 1
    assert result["NestedStack1"][0]["Type"] == "AWS::IAM::Policy"

    assert len(result["NestedStack2"]) == 1
    assert result["NestedStack2"][0]["Type"] == "AWS::IAM::ManagedPolicy"



@patch("builtins.open", new_callable=mock_open, read_data=mock_json_str_2)
def test_extract_iam_resources_bucket_policy(mock_file):
    result = extract_iam_resources("fake/path.json")

    assert "NestedStack1" in result

    assert len(result["NestedStack1"]) == 1
    assert result["NestedStack1"][0]["Type"] == "AWS::S3::BucketPolicy"







##### get_stacks_policies() Tests ##########################################




@patch("builtins.open", new_callable=mock_open, read_data=mock_json_str_empty)
def test_get_empty_stack(mock_file):
    result = json.loads(get_stacks_policies("fake/path.json"))

    assert isinstance(result, dict)
    assert result == {}



@patch("builtins.open", new_callable=mock_open, read_data='{"invalid": "json"')
def test_get_stacks_policies_json_error(mock_file):
    result = get_stacks_policies("fake/path.json")
    assert result.startswith("Error getting stack policies")


@patch("builtins.open", new_callable=mock_open, read_data='{"irrelevant": "json"}')
def test_get_stack_policies_irrelevant_json(mock_file):
    
    result = json.loads(get_stacks_policies("fake/path.json"))
    assert isinstance(result, dict)
    assert result == {}


@patch("builtins.open", new_callable=mock_open, read_data=mock_json_str_1)
def test_get_stacks_policies(mock_file):
    result = json.loads(get_stacks_policies("fake/path.json"))

    assert "NestedStack1" in result
    assert "NestedStack2" in result

    assert "MyTestPolicy" in result["NestedStack1"]
    assert "MyManagedPolicy" in result["NestedStack2"]

    assert isinstance(result["NestedStack1"]["MyTestPolicy"], dict)
    assert isinstance(result["NestedStack2"]["MyManagedPolicy"], dict)



@patch("builtins.open", new_callable=mock_open, read_data=mock_json_str_2)
def test_get_stacks_policies_bucket_policy(mock_file):
    result = json.loads(get_stacks_policies("fake/path.json"))

    assert "NestedStack1" in result
    assert "MyTestPolicy" in result["NestedStack1"]
    assert isinstance(result["NestedStack1"]["MyTestPolicy"], dict)