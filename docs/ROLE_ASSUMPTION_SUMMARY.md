# Role Assumption Feature - Implementation Summary

## What Was Implemented

Role assumption support has been fully implemented, allowing you to use a central identity account to discover resources in multiple target AWS accounts.

## Changes Made

### 1. Database Model (`resources/models.py`)
- Added `role_arn` field to store the IAM role ARN
- Added `external_id` field for additional security

### 2. Migration
- `0009_add_role_assumption_fields.py` - Run with: `poetry run python manage.py migrate`

### 3. Backend Service (`resources/services.py`)
- Added `_assume_role()` method that uses AWS STS to get temporary credentials
- Automatically assumes role if `role_arn` is provided

### 4. Management Command (`resources/management/commands/discover_aws_resources.py`)
- Added `--role-arn` optional parameter
- Added `--external-id` optional parameter
- Saves role configuration with account

### 5. Web UI (`templates/resources/accounts.html`)
- Added "Auth Method" column showing "Role Assumption" or "Direct" badge
- Added tabs in poll form for "Direct Credentials" vs "Role Assumption"
- Added role ARN and external ID fields with tooltips

### 6. Frontend View (`resources/views_frontend.py`)
- Updated `poll_account_view` to handle role assumption parameters
- Shows role ARN in success messages

### 7. Admin Interface (`resources/admin.py`)
- Added "Uses Role" column indicator
- Added role assumption fieldset in account form
- Can view/edit role ARN and external ID

### 8. Documentation
- **ROLE_ASSUMPTION_SETUP.md** - Comprehensive setup guide
- **CLAUDE.md** - Updated with role assumption examples

## How to Use

### Step 1: Run Migration

```bash
poetry run python manage.py migrate
```

### Step 2: Set Up AWS IAM Roles

Follow the detailed instructions in **[ROLE_ASSUMPTION_SETUP.md](ROLE_ASSUMPTION_SETUP.md)**.

Quick version:
1. In each target account, create a role named `ResourceDiscoveryRole`
2. Set trust policy to allow your identity account
3. Attach EC2 read permissions
4. Note the role ARN

### Step 3: Use Role Assumption

#### Option A: Via Web UI

1. Go to http://localhost:8000/accounts/
2. Click **Poll Account**
3. Click the **Role Assumption** tab
4. Fill in:
   - **Account Number:** Target account (e.g., `987654321098`)
   - **Account Name:** "Production Account"
   - **Access Key ID / Secret:** Your identity account credentials
   - **Session Token:** Leave empty or use temp credentials
   - **Regions:** `us-east-1,us-west-2`
   - **Role ARN:** `arn:aws:iam::987654321098:role/ResourceDiscoveryRole`
   - **External ID:** (optional) Your secret external ID
5. Click **Start Polling**

The UI will show:
- A badge indicating "Role Assumption" in the Auth Method column
- Success message with role ARN
- Account saves role configuration for reference

#### Option B: Via Command Line

```bash
poetry run python manage.py discover_aws_resources \
  987654321098 \
  AKIAIOSFODNN7EXAMPLE \
  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  "" \
  us-east-1 us-west-2 \
  --account-name "Production Account" \
  --role-arn "arn:aws:iam::987654321098:role/ResourceDiscoveryRole" \
  --external-id "my-secret-external-id"
```

## What Happens Behind the Scenes

1. **Authentication:** App uses your identity account credentials
2. **Role Assumption:** Calls `sts:AssumeRole` to get temporary credentials for target account
3. **Discovery:** Uses temporary credentials to describe EC2 resources
4. **Storage:** Saves resources to database with role ARN saved in account record
5. **Future Use:** Role ARN is displayed in UI and can be used for subsequent polls

## Benefits

✅ **Single Credential Set:** Use one set of credentials for multiple accounts
✅ **Enhanced Security:** Temporary credentials expire automatically
✅ **Centralized Management:** Manage access through IAM roles
✅ **External ID Support:** Additional layer of security
✅ **Audit Trail:** CloudTrail logs all AssumeRole operations
✅ **Web UI Support:** Full GUI integration, not just CLI

## Verification

To verify it's working:

1. **Check Migration:**
   ```bash
   poetry run python manage.py showmigrations resources
   ```
   Should show `[X] 0009_add_role_assumption_fields`

2. **Check Admin:**
   - Go to http://localhost:8000/admin/resources/awsaccount/
   - Edit an account
   - You should see "Role Assumption Configuration" section

3. **Test Role Assumption:**
   ```bash
   # This should successfully assume role and discover resources
   poetry run python manage.py discover_aws_resources \
     <target_account> \
     <identity_access_key> \
     <identity_secret_key> \
     "" \
     us-east-1 \
     --role-arn "arn:aws:iam::<target_account>:role/ResourceDiscoveryRole"
   ```

## Troubleshooting

### "No module named 'resources.migrations.0009_add_role_assumption_fields'"
**Solution:** Run `poetry run python manage.py migrate`

### "Access Denied" when assuming role
**Solution:** Check ROLE_ASSUMPTION_SETUP.md troubleshooting section - likely trust policy issue

### Role ARN not appearing in UI
**Solution:**
- Clear browser cache
- Check that migration ran successfully
- Verify model has `role_arn` field: `poetry run python manage.py shell` then `from resources.models import AWSAccount; print(AWSAccount._meta.get_fields())`

### Session token field required but I don't have one
**Solution:** Use empty string `""` for long-term credentials

## Next Steps

1. Run the migration
2. Review ROLE_ASSUMPTION_SETUP.md for AWS configuration
3. Set up roles in your target accounts
4. Test with one account first
5. Roll out to additional accounts

## Questions?

- **Setup Help:** See ROLE_ASSUMPTION_SETUP.md
- **Code Changes:** See git diff or this summary
- **AWS IAM:** Refer to AWS documentation links in ROLE_ASSUMPTION_SETUP.md
