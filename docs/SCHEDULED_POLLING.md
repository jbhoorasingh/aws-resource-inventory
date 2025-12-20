# AWS Resource Inventory - Scheduled Polling Guide

This guide explains the automatic scheduled polling feature for EC2 instance role accounts and the resource cleanup behavior during re-polling.

## Table of Contents

- [Overview](#overview)
- [Scheduled Polling](#scheduled-polling)
- [Resource Cleanup Behavior](#resource-cleanup-behavior)
- [Configuration](#configuration)
- [Docker Setup](#docker-setup)
- [Monitoring](#monitoring)
- [Manual Testing](#manual-testing)

## Overview

The AWS Resource Inventory application supports two key features for keeping resource data current:

1. **Scheduled Polling**: Automatically re-poll all EC2 instance role accounts hourly
2. **Resource Cleanup**: Safely remove stale resources during re-polling while preserving shared VPCs

## Scheduled Polling

### How It Works

The scheduled polling feature uses Celery Beat to trigger an hourly task that:

1. Finds all active accounts configured with `instance_role` authentication
2. Creates a parent DiscoveryTask to track overall progress
3. Queues child tasks for each account with staggered countdowns (rate limiting)
4. Each child task re-polls the account using EC2 instance role authentication

### Eligible Accounts

An account is eligible for scheduled polling if it meets ALL of these criteria:

- `auth_method` is set to `instance_role`
- `is_active` is `True`
- `default_role_name` is configured (e.g., `PaloInventoryInspectionRole`)
- `default_regions` has at least one region configured

### Rate Limiting

To prevent overwhelming AWS APIs, scheduled polling uses rate limiting:

- **Max Concurrent**: Maximum number of accounts polled simultaneously
- **Stagger Seconds**: Delay between starting each poll

With default settings (`max_concurrent=2`, `stagger=30s`):

| Account | Start Time |
|---------|------------|
| 1       | 0s         |
| 2       | 30s        |
| 3       | 60s        |
| 4       | 90s        |
| ...     | ...        |

## Resource Cleanup Behavior

### Safe Deletion Strategy

When an account is re-polled, resources are cleaned up safely to handle shared VPCs:

#### Step 1: Delete Account-Specific Resources

These resources are always deleted before saving new ones:

- **ENIs** (owned by the account)
- **ENI Secondary IPs**
- **ENI-SecurityGroup relationships**
- **EC2 Instances** (owned by the account)

#### Step 2: Preserve Shared Resources

These resources are NOT deleted during the initial cleanup because they may be shared across accounts (via VPC Sharing/RAM):

- **VPCs**
- **Subnets**
- **Security Groups**
- **Security Group Rules**

#### Step 3: Clean Up Orphaned VPCs

After saving new resources, orphaned VPCs are cleaned up if they meet ALL of these conditions:

1. VPC is owned by the account being polled
2. VPC was NOT found in the current AWS discovery (no longer exists in AWS)
3. VPC has no remaining ENIs or EC2 instances from any account

This ensures that:
- Shared VPCs (still containing resources from other accounts) are preserved
- VPCs that no longer exist in AWS are removed
- Data stays accurate without risking shared resource deletion

### Example Scenario

Consider a shared VPC scenario:

```
VPC-shared (owner: Account A)
├── Subnet-1
│   ├── ENI-1 (owner: Account A)
│   └── ENI-2 (owner: Account B)  <- From different account!
└── Subnet-2
    └── ENI-3 (owner: Account A)
```

When Account A is re-polled:
1. ENI-1 and ENI-3 are deleted
2. VPC-shared is preserved (because ENI-2 from Account B still exists)
3. New resources discovered in AWS are saved
4. If VPC-shared is still in AWS, it's preserved
5. If VPC-shared is NOT in AWS but ENI-2 exists, VPC is still preserved

## Configuration

### Environment Variables

Add these to your `.env` file:

```env
# Enable/disable scheduled polling (default: true)
SCHEDULED_POLLING_ENABLED=true

# Maximum concurrent account polls (default: 2)
SCHEDULED_POLLING_MAX_CONCURRENT=2

# Seconds between poll starts (default: 30)
SCHEDULED_POLLING_STAGGER_SECONDS=30
```

### Django Settings

The scheduled polling configuration is defined in `aws_inventory/settings.py`:

```python
# Scheduled Polling Configuration
SCHEDULED_POLLING_ENABLED = config('SCHEDULED_POLLING_ENABLED', default=True, cast=bool)
SCHEDULED_POLLING_MAX_CONCURRENT = config('SCHEDULED_POLLING_MAX_CONCURRENT', default=2, cast=int)
SCHEDULED_POLLING_STAGGER_SECONDS = config('SCHEDULED_POLLING_STAGGER_SECONDS', default=30, cast=int)

# Celery Beat Schedule
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'poll-instance-role-accounts-hourly': {
        'task': 'resources.tasks.scheduled_poll_instance_role_accounts',
        'schedule': crontab(minute=0),  # Run at the top of every hour
    },
}
```

### Modifying the Schedule

To change the polling frequency, update `CELERY_BEAT_SCHEDULE` in settings:

```python
# Every 30 minutes
'schedule': crontab(minute='0,30'),

# Every 6 hours
'schedule': crontab(minute=0, hour='*/6'),

# Daily at midnight
'schedule': crontab(minute=0, hour=0),
```

## Docker Setup

### Production (docker-compose.yml)

The production setup includes a dedicated Celery Beat service:

```yaml
# Celery Beat Scheduler (for periodic tasks)
celery-beat:
  build:
    context: .
    dockerfile: Dockerfile
    target: production
  container_name: aws-inventory-celery-beat
  command: celery -A aws_inventory beat -l INFO
  environment:
    # ... standard Django/Celery settings ...
    SCHEDULED_POLLING_ENABLED: ${SCHEDULED_POLLING_ENABLED:-true}
    SCHEDULED_POLLING_MAX_CONCURRENT: ${SCHEDULED_POLLING_MAX_CONCURRENT:-2}
    SCHEDULED_POLLING_STAGGER_SECONDS: ${SCHEDULED_POLLING_STAGGER_SECONDS:-30}
  depends_on:
    - db
    - redis
  restart: unless-stopped
```

### Start Services

```bash
# Start all services including celery-beat
docker-compose up -d

# View celery-beat logs
docker-compose logs -f celery-beat

# View celery worker logs (where tasks execute)
docker-compose logs -f celery
```

### Disable Scheduled Polling

To temporarily disable scheduled polling without stopping the service:

```bash
# Set environment variable
export SCHEDULED_POLLING_ENABLED=false
docker-compose up -d celery-beat
```

Or add to `.env`:

```env
SCHEDULED_POLLING_ENABLED=false
```

## Monitoring

### View Scheduled Tasks

The tasks page shows all discovery tasks including scheduled polls:

- **Web UI**: `http://localhost:8000/tasks/`
- Tasks initiated by scheduled polling have no `initiated_by` user

### Check Celery Beat Status

```bash
# View celery-beat logs
docker-compose logs -f celery-beat

# Check next scheduled run
docker-compose exec celery-beat celery -A aws_inventory inspect scheduled
```

### Check Worker Queue

```bash
# View pending tasks
docker-compose exec celery celery -A aws_inventory inspect active

# View reserved tasks
docker-compose exec celery celery -A aws_inventory inspect reserved
```

## Manual Testing

### Trigger Scheduled Poll Manually

```bash
# Using Django shell
docker-compose exec web python manage.py shell

>>> from resources.tasks import scheduled_poll_instance_role_accounts
>>> result = scheduled_poll_instance_role_accounts.delay()
>>> print(result.get())  # Wait for result
```

### Test Resource Cleanup

```bash
# Using Django shell
docker-compose exec web python manage.py shell

>>> from resources.tasks import _delete_account_enis_and_ec2, _cleanup_orphaned_vpcs
>>> from resources.models import AWSAccount

# Test deletion for an account
>>> result = _delete_account_enis_and_ec2('123456789012')
>>> print(result)  # {'enis': 5, 'ec2_instances': 2, ...}

# Test orphan cleanup
>>> result = _cleanup_orphaned_vpcs('123456789012', {'vpc-active-1', 'vpc-active-2'})
>>> print(result)  # {'vpcs': 1, 'subnets': 3, ...}
```

### Verify Account Eligibility

```bash
docker-compose exec web python manage.py shell

>>> from resources.models import AWSAccount

# List eligible accounts
>>> eligible = AWSAccount.objects.filter(
...     auth_method='instance_role',
...     is_active=True,
... ).exclude(default_regions=[]).exclude(default_role_name='')
>>> for a in eligible:
...     print(f"{a.account_id}: {a.account_name} - regions: {a.default_regions}")
```

## Troubleshooting

### Scheduled Polling Not Running

1. **Check celery-beat is running**:
   ```bash
   docker-compose ps celery-beat
   ```

2. **Check SCHEDULED_POLLING_ENABLED**:
   ```bash
   docker-compose exec celery-beat env | grep SCHEDULED
   ```

3. **Check celery-beat logs**:
   ```bash
   docker-compose logs celery-beat | grep -i error
   ```

### Tasks Failing

1. **Check celery worker logs**:
   ```bash
   docker-compose logs celery | grep -i error
   ```

2. **Check task status in database**:
   ```bash
   docker-compose exec web python manage.py shell
   >>> from resources.models import DiscoveryTask
   >>> failed = DiscoveryTask.objects.filter(status='failed').order_by('-created_at')[:5]
   >>> for t in failed:
   ...     print(f"{t.id}: {t.error_message}")
   ```

### VPCs Not Being Cleaned Up

VPCs are only deleted if they:
1. Are NOT in the current discovery results (no longer exist in AWS)
2. Have no remaining ENIs or EC2 instances

Check if there are remaining resources:
```bash
docker-compose exec web python manage.py shell
>>> from resources.models import VPC, ENI, EC2Instance
>>> vpc = VPC.objects.get(vpc_id='vpc-xxxxx')
>>> print(f"ENIs: {ENI.objects.filter(subnet__vpc=vpc).count()}")
>>> print(f"EC2: {EC2Instance.objects.filter(vpc=vpc).count()}")
```
