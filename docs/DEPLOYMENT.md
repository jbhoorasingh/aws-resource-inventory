# AWS Resource Inventory - Docker Deployment Guide

This guide provides instructions for deploying AWS Resource Inventory using Docker and Docker Compose for production environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Production Deployment](#production-deployment)
- [Configuration](#configuration)
- [Management Commands](#management-commands)
- [Monitoring and Logs](#monitoring-and-logs)
- [Backup and Restore](#backup-and-restore)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Docker Engine 24.0+ ([Install Docker](https://docs.docker.com/get-docker/))
- Docker Compose 2.0+ ([Install Docker Compose](https://docs.docker.com/compose/install/))
- 2GB+ RAM available
- 10GB+ disk space

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/aws-resource-inventory.git
cd aws-resource-inventory
```

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.production.example .env.production

# Edit the file with your configuration
nano .env.production
```

**Important:** Update these values in `.env.production`:

- `SECRET_KEY` - Generate a secure random key
- `POSTGRES_PASSWORD` - Set a strong database password
- `DJANGO_SUPERUSER_PASSWORD` - Set admin password
- `ALLOWED_HOSTS` - Add your domain/IP addresses

### 3. Generate SECRET_KEY

```bash
# Generate a secure random key
python3 -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```

### 4. Start Services

```bash
# Build and start all services
docker-compose --env-file .env.production up -d

# View logs
docker-compose logs -f
```

### 5. Access the Application

- **Web UI**: http://localhost
- **Admin Panel**: http://localhost/admin/
- **API**: http://localhost/api/
- **EDL Endpoints**: http://localhost/edl/

Login with the username and password from `DJANGO_SUPERUSER_USERNAME` and `DJANGO_SUPERUSER_PASSWORD`.

## Production Deployment

### Security Hardening

#### 1. Use Strong Passwords

```bash
# Generate strong passwords
openssl rand -base64 32
```

#### 2. Enable HTTPS (Recommended)

**Option A: Using Let's Encrypt with Certbot**

```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot certonly --standalone -d your-domain.com

# Create SSL directory
mkdir -p ssl
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem ssl/key.pem
sudo chown -R $USER:$USER ssl/
```

**Option B: Using Self-Signed Certificates (Development Only)**

```bash
mkdir -p ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem -out ssl/cert.pem
```

Uncomment the HTTPS server block in `nginx.conf` and update the domain name.

#### 3. Configure Firewall

```bash
# Allow only necessary ports
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

#### 4. Restrict Database Access

The PostgreSQL database is only accessible from within the Docker network by default. Do not expose port 5432 externally.

### Environment Variables for Production

Create `.env.production` with these settings:

```env
# Django Settings
SECRET_KEY=your-generated-secret-key
DEBUG=False
ALLOWED_HOSTS=your-domain.com,www.your-domain.com

# Database
POSTGRES_DB=awsinventory
POSTGRES_USER=awsinventory
POSTGRES_PASSWORD=your-secure-password

# Superuser
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_PASSWORD=your-admin-password
DJANGO_SUPERUSER_EMAIL=admin@your-domain.com

# AWS (optional - can use IAM roles instead)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
```

### Running in Production

```bash
# Start services in detached mode
docker-compose --env-file .env.production up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f web

# Stop services
docker-compose down

# Stop and remove volumes (careful - deletes database!)
docker-compose down -v
```

## Configuration

### Scaling Workers

Update `docker-compose.yml` to adjust Gunicorn workers:

```yaml
services:
  web:
    command: gunicorn aws_inventory.wsgi:application --bind 0.0.0.0:8000 --workers 8 --timeout 120
```

**Formula**: Workers = (2 × CPU cores) + 1

### Custom Nginx Configuration

Edit `nginx.conf` to customize:

- Rate limiting
- Cache settings
- SSL/TLS configuration
- Custom headers

Reload nginx after changes:

```bash
docker-compose exec nginx nginx -s reload
```

### Database Tuning

For large deployments, create `docker-compose.override.yml`:

```yaml
version: '3.9'
services:
  db:
    environment:
      POSTGRES_SHARED_BUFFERS: 256MB
      POSTGRES_EFFECTIVE_CACHE_SIZE: 1GB
      POSTGRES_MAX_CONNECTIONS: 200
```

## Management Commands

### Run Django Management Commands

```bash
# Create migrations
docker-compose exec web python manage.py makemigrations

# Apply migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Open Django shell
docker-compose exec web python manage.py shell

# Collect static files
docker-compose exec web python manage.py collectstatic --noinput
```

### Discover AWS Resources

```bash
# Run discovery command
docker-compose exec web python manage.py discover_aws_resources \
  123456789012 \
  AKIAIOSFODNN7EXAMPLE \
  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  "" \
  us-east-1 us-west-2 \
  --account-name "Production Account"

# With role assumption
docker-compose exec web python manage.py discover_aws_resources \
  123456789012 \
  AKIAIOSFODNN7EXAMPLE \
  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  "" \
  us-east-1 \
  --role-arn "arn:aws:iam::123456789012:role/AWSResourceDiscovery" \
  --external-id "your-external-id"
```

### Database Operations

```bash
# Database shell
docker-compose exec db psql -U awsinventory -d awsinventory

# Create database backup
docker-compose exec db pg_dump -U awsinventory awsinventory > backup.sql

# Restore database
cat backup.sql | docker-compose exec -T db psql -U awsinventory -d awsinventory
```

## Monitoring and Logs

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f web
docker-compose logs -f db
docker-compose logs -f nginx

# Last 100 lines
docker-compose logs --tail=100 web
```

### Health Checks

```bash
# Application health
curl http://localhost/health/

# Check service status
docker-compose ps

# View resource usage
docker stats
```

### Application Logs

Application logs are stored in the `logs` volume:

```bash
# View Django logs
docker-compose exec web tail -f /app/logs/app.log

# View all log files
docker-compose exec web ls -la /app/logs/
```

## Backup and Restore

### Automated Backups

Create a backup script `/usr/local/bin/backup-aws-inventory.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/backups/aws-inventory"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup database
docker-compose exec -T db pg_dump -U awsinventory awsinventory | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# Backup static files
docker-compose exec -T web tar czf - /app/staticfiles > "$BACKUP_DIR/static_$DATE.tar.gz"

# Keep only last 7 days
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
```

Schedule with cron:

```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * /usr/local/bin/backup-aws-inventory.sh
```

### Restore from Backup

```bash
# Stop the application
docker-compose down

# Restore database
gunzip < /backups/aws-inventory/db_20250114_020000.sql.gz | \
  docker-compose exec -T db psql -U awsinventory -d awsinventory

# Restart application
docker-compose up -d
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs web

# Check service status
docker-compose ps

# Rebuild containers
docker-compose build --no-cache
docker-compose up -d
```

### Database Connection Issues

```bash
# Check if database is running
docker-compose ps db

# Check database logs
docker-compose logs db

# Verify connection
docker-compose exec web python manage.py dbshell
```

### Permission Issues

```bash
# Fix staticfiles permissions
docker-compose exec web chown -R appuser:appuser /app/staticfiles

# Rebuild with correct permissions
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### High Memory Usage

```bash
# Check resource usage
docker stats

# Reduce Gunicorn workers in docker-compose.yml
# workers = (2 × CPU cores) + 1

# Restart services
docker-compose restart web
```

### Clear Cache and Reset

```bash
# Stop all services
docker-compose down

# Remove all data (WARNING: Deletes database!)
docker-compose down -v

# Rebuild and start fresh
docker-compose build --no-cache
docker-compose --env-file .env.production up -d
```

## Production Checklist

Before deploying to production:

- [ ] Generated strong `SECRET_KEY`
- [ ] Set `DEBUG=False`
- [ ] Configured `ALLOWED_HOSTS` with your domain
- [ ] Set strong database password
- [ ] Configured HTTPS/SSL certificates
- [ ] Set up firewall rules
- [ ] Configured automated backups
- [ ] Set up monitoring/alerting
- [ ] Documented AWS credentials management
- [ ] Tested database restore procedure
- [ ] Reviewed nginx rate limiting
- [ ] Configured log rotation
- [ ] Set up health check monitoring

## Support

For issues or questions:

- GitHub Issues: https://github.com/your-org/aws-resource-inventory/issues
- Documentation: https://github.com/your-org/aws-resource-inventory/wiki

## License

See [LICENSE](LICENSE) file for details.
