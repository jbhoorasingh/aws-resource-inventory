# AWS Resource Inventory

A Django-based application for discovering, tracking, and managing AWS networking resources across multiple AWS accounts and regions. Features include a REST API, web interface, and External Dynamic List (EDL) endpoints for Palo Alto Networks firewall integration.

## Features

- **Multi-Account & Multi-Region Support**: Discover resources across multiple AWS accounts and regions
- **Comprehensive Resource Tracking**: Track VPCs, Subnets, ENIs, Security Groups, and their relationships
- **REST API**: Full-featured API for programmatic access to resource data
- **Web Interface**: User-friendly web UI for viewing and managing resources
- **External Dynamic Lists (EDL)**: Integration with Palo Alto Networks firewalls for dynamic IP address lists
- **IP Address Lookup**: Find ENIs by primary, public, or secondary IP addresses

## Supported AWS Resources

- **VPCs** (Virtual Private Clouds)
- **Subnets**
- **ENIs** (Elastic Network Interfaces) with primary and secondary IPs
- **Security Groups** with detailed ingress/egress rules
- **Resource Attachments** (EC2 instances, ELBs, etc.)

## Quick Start

### Prerequisites

- Python 3.12+
- Poetry (for dependency management)
- AWS credentials with appropriate permissions

### Installation

1. Clone the repository:
```bash
git clone https://github.com/jbhoorasingh/aws-resource-inventory.git
cd aws-resource-inventory
```

2. Install dependencies:
```bash
poetry install
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Restore project files (if needed):
```bash
git checkout 58bdc2d -- .
```

5. Run database migrations:
```bash
poetry run python manage.py migrate
```

6. Create a superuser:
```bash
poetry run python manage.py createsuperuser
```

7. Start the development server:
```bash
poetry run python manage.py runserver
```

The application will be available at:
- **Web UI**: http://localhost:8000/
- **Admin Panel**: http://localhost:8000/admin/
- **API**: http://localhost:8000/api/
- **EDL**: http://localhost:8000/edl/

## Usage

### Discovering AWS Resources

Use the `discover_aws_resources` management command to poll AWS and populate the database:

```bash
poetry run python manage.py discover_aws_resources \
  <account_number> \
  <access_key_id> \
  <secret_access_key> \
  <session_token> \
  <region1> [region2...] \
  --account-name "Account Name"
```

Example:
```bash
poetry run python manage.py discover_aws_resources \
  123456789012 \
  AKIAIOSFODNN7EXAMPLE \
  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  "" \
  us-east-1 us-west-2 \
  --account-name "Production Account"
```

**Dry Run Mode** (test without saving):
```bash
poetry run python manage.py discover_aws_resources ... --dry-run
```

### API Endpoints

The REST API provides comprehensive access to all resource data:

- **Accounts**: `/api/accounts/`
- **VPCs**: `/api/vpcs/`
- **Subnets**: `/api/subnets/`
- **Security Groups**: `/api/security-groups/`
- **ENIs**: `/api/enis/`

#### Special ENI Endpoints

- Find by IP: `/api/enis/by_ip/?ip=<address>`
- Public IPs only: `/api/enis/with_public_ip/`
- Statistics: `/api/enis/summary/`
- Filter by region: `/api/enis/by_region/?region=<region>`
- Filter by owner: `/api/enis/by_owner_account/?owner_account=<id>`

All endpoints support filtering, pagination, and ordering.

### External Dynamic Lists (EDL)

EDL endpoints generate text files with IP addresses for Palo Alto Networks firewalls:

- **EDL Summary**: `/edl/`
- **Account IPs**: `/edl/account/<account_id>/`
- **Security Group IPs**: `/edl/sg/<sg_id>/`
- **JSON Metadata**: `/edl/account/<account_id>/json/` or `/edl/sg/<sg_id>/json/`

EDL Format:
```
10.0.1.5 # eni-0123456789abcdef0, primary
10.0.1.6 # eni-0123456789abcdef0, secondary
```

EDL responses are cached for 5 minutes.

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

**Django Configuration:**
```bash
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
```

**AWS Configuration:**
```bash
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
AWS_SESSION_TOKEN=your-session-token  # Optional, for temporary credentials
AWS_DEFAULT_REGION=us-east-1
AWS_REGIONS=us-east-1,us-west-2,eu-west-1
```

**Database** (optional):
```bash
# Defaults to SQLite if not specified
DATABASE_URL=postgresql://user:password@localhost:5432/aws_inventory
```

### AWS Permissions

The application requires the following AWS permissions:
- `ec2:DescribeVpcs`
- `ec2:DescribeSubnets`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeNetworkInterfaces`
- `sts:GetCallerIdentity`

## Architecture

### Data Model

```
AWSAccount
    └── Tracks account metadata and last poll time

VPC
    ├── Subnet
    │   └── ENI (Elastic Network Interface)
    │       ├── ENISecondaryIP (secondary IPs)
    │       └── ENISecurityGroup (many-to-many with SecurityGroup)
    └── SecurityGroup
        └── SecurityGroupRule (ingress/egress rules)
```

### Key Components

- **Discovery Service** (`resources/services.py`): Interacts with AWS APIs via boto3
- **Management Command** (`resources/management/commands/`): CLI for resource discovery
- **REST API** (`resources/views.py`): DRF ViewSets for API endpoints
- **Web UI** (`resources/views_frontend.py`): Server-side rendered views
- **EDL** (`resources/views_edl.py`): Palo Alto firewall integration

## Development

### Running Tests

```bash
poetry run pytest
```

### Database Migrations

```bash
# Create new migration
poetry run python manage.py makemigrations

# Apply migrations
poetry run python manage.py migrate
```

### Adding Dependencies

```bash
# Production dependency
poetry add package-name

# Development dependency
poetry add --group dev package-name
```

### Django Shell

```bash
poetry run python manage.py shell
```

## Technology Stack

- **Django 4.2.7**: Web framework
- **Django REST Framework 3.14.0**: REST API
- **boto3 1.34.0**: AWS SDK
- **PostgreSQL/SQLite**: Database
- **Poetry**: Dependency management

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]

## Support

[Add support contact or issue tracker info here]
