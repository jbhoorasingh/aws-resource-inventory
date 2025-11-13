#!/usr/bin/env python
"""
Test script to verify AWS credentials and role assumption
"""
import boto3
import sys

def test_credentials(access_key, secret_key, session_token=None):
    """Test if credentials are valid"""
    print("=" * 60)
    print("Testing Identity Account Credentials")
    print("=" * 60)

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        sts = session.client('sts')
        identity = sts.get_caller_identity()

        print("✓ Credentials are VALID!")
        print(f"  Account: {identity['Account']}")
        print(f"  User/Role: {identity['Arn']}")
        print(f"  User ID: {identity['UserId']}")
        return True, identity['Account']
    except Exception as e:
        print("✗ Credentials are INVALID!")
        print(f"  Error: {e}")
        return False, None


def test_role_assumption(access_key, secret_key, session_token, role_arn, external_id=None):
    """Test if role assumption works"""
    print("\n" + "=" * 60)
    print("Testing Role Assumption")
    print("=" * 60)
    print(f"Role ARN: {role_arn}")
    if external_id:
        print(f"External ID: {external_id}")

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        sts = session.client('sts')

        # Build assume role parameters
        params = {
            'RoleArn': role_arn,
            'RoleSessionName': 'TestSession'
        }
        if external_id:
            params['ExternalId'] = external_id

        response = sts.assume_role(**params)

        print("✓ Role assumption SUCCESSFUL!")
        print(f"  Assumed Role: {response['AssumedRoleUser']['Arn']}")
        print(f"  Session expiry: {response['Credentials']['Expiration']}")

        # Test using assumed credentials
        assumed_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        assumed_sts = assumed_session.client('sts')
        assumed_identity = assumed_sts.get_caller_identity()
        print(f"  Target Account: {assumed_identity['Account']}")

        return True
    except Exception as e:
        print("✗ Role assumption FAILED!")
        print(f"  Error: {e}")
        print("\nPossible issues:")
        print("  - Trust policy doesn't allow your identity account")
        print("  - External ID mismatch")
        print("  - Role doesn't exist")
        print("  - Identity account lacks sts:AssumeRole permission")
        return False


if __name__ == "__main__":
    print("\nAWS Credentials & Role Assumption Tester")
    print("=" * 60)

    # Get credentials from user
    print("\nEnter your IDENTITY account credentials:")
    access_key = input("Access Key ID: ").strip()
    secret_key = input("Secret Access Key: ").strip()
    session_token = input("Session Token (press Enter if none): ").strip()

    if not session_token:
        session_token = None

    # Test basic credentials
    valid, account_id = test_credentials(access_key, secret_key, session_token)

    if not valid:
        print("\n⚠️  Fix your credentials first before testing role assumption!")
        sys.exit(1)

    # Ask about role assumption test
    print("\n" + "=" * 60)
    test_role = input("\nDo you want to test role assumption? (y/n): ").strip().lower()

    if test_role == 'y':
        print("\nEnter role assumption details:")
        role_arn = input("Role ARN (e.g., arn:aws:iam::123456789012:role/ResourceDiscoveryRole): ").strip()
        external_id = input("External ID (press Enter if none): ").strip()

        if not external_id:
            external_id = None

        test_role_assumption(access_key, secret_key, session_token, role_arn, external_id)

    print("\n" + "=" * 60)
    print("Testing complete!")
    print("=" * 60)
