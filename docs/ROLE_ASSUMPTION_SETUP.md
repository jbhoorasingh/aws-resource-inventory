# AWS Role Assumption Setup Guide

This guide explains how to configure AWS IAM roles for cross-account resource discovery using role assumption.

## Overview

Role assumption allows you to use credentials from a **central identity account** to discover resources in multiple **target accounts** by assuming IAM roles. This approach:

- Reduces credential management (one set of credentials for multiple accounts)
- Improves security with temporary credentials
- Follows AWS best practices for multi-account architectures
- Supports external ID for additional security

## Architecture

```
┌─────────────────────────┐
│  Identity Account       │
│  (111111111111)         │
│  ┌──────────────────┐   │
│  │ IAM User/Role    │   │
│  │ (Your Creds)     │   │
│  └──────────────────┘   │
└───────────┬─────────────┘
            │ AssumeRole
            ▼
┌─────────────────────────┐
│  Target Account 1       │
│  (222222222222)         │
│  ┌──────────────────┐   │
│  │ ResourceDiscovery│   │
│  │ Role             │   │
│  └──────────────────┘   │
└─────────────────────────┘
            │ AssumeRole
            ▼
┌─────────────────────────┐
│  Target Account 2       │
│  (333333333333)         │
│  ┌──────────────────┐   │
│  │ ResourceDiscovery│   │
│  │ Role             │   │
│  └──────────────────┘   │
└─────────────────────────┘
```

## Step 1: Create IAM Role in Target Account

For each target account you want to discover resources in, create an IAM role.

### Via AWS Console

1. **Navigate to IAM**
   - Log into the target AWS account
   - Go to IAM → Roles → Create role

2. **Select Trusted Entity**
   - Select "AWS account"
   - Choose "Another AWS account"
   - Enter the **Identity Account ID** (e.g., `111111111111`)
   - Optionally check "Require external ID" and enter a unique string (recommended for security)

3. **Attach Permissions**
   - Attach the `ReadOnlyAccess` managed policy, OR
   - Create a custom policy with these permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

4. **Name the Role**
   - Name: `ResourceDiscoveryRole`
   - Description: "Role for AWS Resource Inventory discovery"
   - Create role

### Via AWS CLI

```bash
# Set variables
IDENTITY_ACCOUNT_ID="111111111111"
TARGET_ACCOUNT_ID="222222222222"
EXTERNAL_ID="my-unique-external-id-12345"  # Optional but recommended

# Create trust policy file
cat > trust-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${IDENTITY_ACCOUNT_ID}:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "${EXTERNAL_ID}"
                }
            }
        }
    ]
}
EOF

# Create the role
aws iam create-role \
    --role-name ResourceDiscoveryRole \
    --assume-role-policy-document file://trust-policy.json \
    --description "Role for AWS Resource Inventory discovery"

# Attach ReadOnlyAccess policy (or use custom policy above)
aws iam attach-role-policy \
    --role-name ResourceDiscoveryRole \
    --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Get the role ARN
aws iam get-role \
    --role-name ResourceDiscoveryRole \
    --query 'Role.Arn' \
    --output text
```

**Output:** `arn:aws:iam::222222222222:role/ResourceDiscoveryRole`

Save this ARN - you'll need it for discovery!

## Step 2: Configure Identity Account

The identity account needs credentials (IAM user or role) with permission to assume roles in target accounts.

### Option A: Create IAM User (for CLI/Web UI usage)

```bash
# Create IAM user
aws iam create-user --user-name resource-discovery-user

# Create access key
aws iam create-access-key --user-name resource-discovery-user

# Attach policy allowing AssumeRole
cat > assume-role-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/ResourceDiscoveryRole"
        }
    ]
}
EOF

aws iam put-user-policy \
    --user-name resource-discovery-user \
    --policy-name AssumeResourceDiscoveryRole \
    --policy-document file://assume-role-policy.json
```

Save the Access Key ID and Secret Access Key from the output!

### Option B: Use Existing IAM Identity

If you're using an existing IAM user or role, ensure it has the `sts:AssumeRole` permission:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": [
                "arn:aws:iam::222222222222:role/ResourceDiscoveryRole",
                "arn:aws:iam::333333333333:role/ResourceDiscoveryRole"
            ]
        }
    ]
}
```

## Step 3: Use Role Assumption in Application

### Via Command Line

```bash
poetry run python manage.py discover_aws_resources \
  222222222222 \
  AKIAIOSFODNN7EXAMPLE \
  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  "" \
  us-east-1 us-west-2 \
  --account-name "Production Account" \
  --role-arn "arn:aws:iam::222222222222:role/ResourceDiscoveryRole" \
  --external-id "my-unique-external-id-12345"
```

**Parameters:**
- `222222222222` - Target account number
- `AKIAIO...` - Access key from identity account
- `wJalr...` - Secret key from identity account
- `""` - Session token (empty for long-term credentials)
- `us-east-1 us-west-2` - Regions to scan
- `--role-arn` - ARN of role in target account
- `--external-id` - External ID (if configured in trust policy)

### Via Web UI

1. Navigate to **Accounts** page
2. Click **Poll Account**
3. Select the **Role Assumption** tab
4. Fill in:
   - **Account Number:** Target account (e.g., `222222222222`)
   - **Account Name:** Friendly name
   - **Access Key ID / Secret / Token:** Identity account credentials
   - **Regions:** Comma-separated list
   - **Role ARN:** `arn:aws:iam::222222222222:role/ResourceDiscoveryRole`
   - **External ID:** (if used)
5. Click **Start Polling**

## Troubleshooting

### Error: "Access Denied" when assuming role

**Cause:** Trust policy doesn't allow the identity account

**Solution:**
1. Verify the identity account ID in the target role's trust policy
2. Check that the external ID matches (if used)
3. Ensure the identity account credentials have `sts:AssumeRole` permission

```bash
# Test role assumption manually
aws sts assume-role \
    --role-arn "arn:aws:iam::222222222222:role/ResourceDiscoveryRole" \
    --role-session-name "test-session" \
    --external-id "my-unique-external-id-12345"
```

### Error: "User is not authorized to perform: sts:AssumeRole"

**Cause:** Identity account user/role lacks permission

**Solution:** Add `sts:AssumeRole` permission to the identity account user/role (see Step 2)

### Error: "External ID does not match"

**Cause:** Mismatch between external ID in trust policy and command

**Solution:**
- Verify external ID in target role trust policy
- Ensure you're passing the same value via `--external-id`
- If not using external ID, remove it from both trust policy and command

## Best Practices

1. **Use External IDs:** Always use external IDs for additional security, especially if third parties have access
2. **Least Privilege:** Grant only necessary EC2 permissions, not `ReadOnlyAccess`
3. **Rotate Credentials:** Regularly rotate identity account access keys
4. **Audit Logs:** Enable CloudTrail to track AssumeRole calls
5. **Naming Convention:** Use consistent role names across accounts (e.g., `ResourceDiscoveryRole`)
6. **Session Names:** The app uses `AWSResourceInventoryDiscovery` as the session name for tracking

## Security Considerations

- **Trust Policy:** Only allow specific identity accounts, not `"*"`
- **External ID:** Acts as a password; keep it secret
- **Temporary Credentials:** Assumed role credentials are temporary (default 1 hour)
- **Scope:** Role permissions only grant access to resources in the target account
- **Revocation:** Deleting or modifying the target role immediately revokes access

## Multiple Accounts Setup Script

For organizations with many accounts:

```bash
#!/bin/bash
# deploy-discovery-roles.sh

IDENTITY_ACCOUNT="111111111111"
EXTERNAL_ID="my-unique-external-id-12345"
TARGET_ACCOUNTS=("222222222222" "333333333333" "444444444444")

for ACCOUNT in "${TARGET_ACCOUNTS[@]}"; do
    echo "Setting up role in account $ACCOUNT..."

    # Assume a role in the target account (requires AWS Organizations or pre-existing access)
    # Then create the ResourceDiscoveryRole

    # This is a simplified example - actual implementation depends on your org setup
done
```

## Reference: Complete Trust Policy Examples

### With External ID (Recommended)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::111111111111:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "my-unique-external-id-12345"
                }
            }
        }
    ]
}
```

### Without External ID

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::111111111111:root"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

### Allowing Specific IAM User

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::111111111111:user/resource-discovery-user"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

## Additional Resources

- [AWS STS AssumeRole Documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [IAM Tutorial: Delegate Access Across AWS Accounts](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html)
- [How to Use External ID for Third-Party Access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)
