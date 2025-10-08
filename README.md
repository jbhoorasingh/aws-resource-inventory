# AWS Resource Inventory

A Django application for discovering and tracking AWS resources with IP addresses and ENIs across multiple regions and accounts.

## Features

- **Multi-Account Support**: Track resources across different AWS accounts
- **Multi-Region Discovery**: Scan resources in specified AWS regions
- **Comprehensive Resource Tracking**:
  - VPCs with CIDR blocks and owner accounts
  - Subnets with names, CIDRs, AZs, and owner accounts
  - ENIs with primary/secondary IPs, security groups, and attached resources
  - Security Groups with detailed information
- **REST API**: Query and filter resources via REST endpoints
- **Admin Interface**: Manage resources through Django admin
- **Management Commands**: Automated resource discovery via CLI

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd aws-resource-inventory
   ```

2. **Create and activate virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**:
   ```bash
   cp env.example .env
   # Edit .env with your AWS credentials and settings
   ```

5. **Run migrations**:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Create superuser**:
   ```bash
   python manage.py createsuperuser
   ```

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# AWS Credentials
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
AWS_SESSION_TOKEN=your-session-token-if-using-temporary-credentials

# AWS Configuration
AWS_DEFAULT_REGION=us-east-1
AWS_REGIONS=us-east-1,us-west-2,eu-west-1
```

### AWS Credentials

The application supports multiple credential methods:

1. **Environment Variables** (recommended for temporary credentials)
2. **AWS Credentials File** (`~/.aws/credentials`)
3. **IAM Roles** (if running on EC2)

## Usage

### Discovery Commands

#### Basic Discovery
```bash
python manage.py discover_aws_resources \
  123456789012 \
  AKIA... \
  your-secret-access-key \
  your-session-token \
  us-east-1 us-west-2
```

#### With Account Name
```bash
python manage.py discover_aws_resources \
  123456789012 \
  AKIA... \
  your-secret-access-key \
  your-session-token \
  us-east-1 us-west-2 \
  --account-name "Production Account"
```

#### Dry Run
```bash
python manage.py discover_aws_resources \
  123456789012 \
  AKIA... \
  your-secret-access-key \
  your-session-token \
  us-east-1 us-west-2 \
  --dry-run
```

### Running the Application

1. **Start the development server**:
   ```bash
   python manage.py runserver
   ```

2. **Access the admin interface**:
   - URL: http://localhost:8000/admin/
   - Login with your superuser credentials

3. **Access the API**:
   - Base URL: http://localhost:8000/api/
   - API Documentation: http://localhost:8000/api/

## API Endpoints

### Accounts
- `GET /api/accounts/` - List all AWS accounts
- `GET /api/accounts/{id}/` - Get account details

### VPCs
- `GET /api/vpcs/` - List all VPCs
- `GET /api/vpcs/{id}/` - Get VPC details
- Filter by: `account`, `region`, `is_default`, `state`

### Subnets
- `GET /api/subnets/` - List all subnets
- `GET /api/subnets/{id}/` - Get subnet details
- Filter by: `vpc`, `availability_zone`, `state`

### Security Groups
- `GET /api/security-groups/` - List all security groups
- `GET /api/security-groups/{id}/` - Get security group details
- Filter by: `vpc`, `account`, `region`

### ENIs
- `GET /api/enis/` - List all ENIs
- `GET /api/enis/{id}/` - Get ENI details
- `GET /api/enis/by_ip/?ip=10.0.1.100` - Find ENI by IP address
- `GET /api/enis/with_public_ip/` - ENIs with public IPs
- `GET /api/enis/attached_resources/` - ENIs with attached resources
- `GET /api/enis/summary/` - Resource summary statistics
- `GET /api/enis/by_region/?region=us-east-1` - ENIs by region
- `GET /api/enis/by_account/?account_id=123456789012` - ENIs by account

## Data Models

### AWSAccount
- `account_id`: AWS Account ID
- `account_name`: Account name/alias
- `is_active`: Whether account is monitored

### VPC
- `vpc_id`: VPC ID
- `account`: Associated AWS account
- `region`: AWS region
- `cidr_block`: VPC CIDR block
- `owner_account`: Owner account ID (for shared VPCs)
- `is_default`: Whether this is the default VPC
- `state`: VPC state

### Subnet
- `subnet_id`: Subnet ID
- `vpc`: Associated VPC
- `name`: Subnet name tag
- `cidr_block`: Subnet CIDR block
- `availability_zone`: AZ
- `owner_account`: Owner account ID (for shared subnets)
- `state`: Subnet state

### ENI
- `eni_id`: ENI ID
- `subnet`: Associated subnet
- `name`: ENI name tag
- `description`: ENI description
- `interface_type`: Interface type
- `status`: ENI status
- `mac_address`: MAC address
- `private_ip_address`: Primary private IP
- `public_ip_address`: Public IP (if assigned)
- `attached_resource_id`: ID of attached resource
- `attached_resource_type`: Type of attached resource

### ENISecondaryIP
- `eni`: Associated ENI
- `ip_address`: Secondary IP address

### ENISecurityGroup
- `eni`: Associated ENI
- `security_group`: Associated security group

## Examples

### Find ENI by IP Address
```bash
curl "http://localhost:8000/api/enis/by_ip/?ip=10.0.1.100"
```

### Get All ENIs with Public IPs
```bash
curl "http://localhost:8000/api/enis/with_public_ip/"
```

### Get Resource Summary
```bash
curl "http://localhost:8000/api/enis/summary/"
```

### Filter ENIs by Region
```bash
curl "http://localhost:8000/api/enis/by_region/?region=us-east-1"
```

### Filter ENIs by Account
```bash
curl "http://localhost:8000/api/enis/by_account/?account_id=123456789012"
```

## Scheduling Discovery

### Using Cron
Add to your crontab to run discovery every hour:
```bash
0 * * * * cd /path/to/aws-resource-inventory && python manage.py discover_aws_resources
```

### Using Celery (Advanced)
For production environments, consider using Celery for scheduled discovery tasks.

## Troubleshooting

### Common Issues

1. **AWS Credentials**: Ensure your AWS credentials have the necessary permissions:
   - `ec2:DescribeVpcs`
   - `ec2:DescribeSubnets`
   - `ec2:DescribeNetworkInterfaces`
   - `ec2:DescribeSecurityGroups`
   - `sts:GetCallerIdentity`

2. **Region Access**: Some regions may not be accessible depending on your AWS account configuration.

3. **Rate Limiting**: AWS API has rate limits. The application includes basic error handling, but you may need to implement retry logic for large-scale deployments.

### Logging

Enable detailed logging by setting the log level in your Django settings:
```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'aws_inventory.log',
        },
    },
    'loggers': {
        'resources': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
