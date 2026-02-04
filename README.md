# CertWarden Deploy

A Python-based certificate deployment tool for [CertWarden](https://www.certwarden.com/) that automatically retrieves SSL/TLS certificates and deploys them to your servers.

## Features

- **Automated Certificate Retrieval**: Fetch certificates, private keys, and certificate chains from CertWarden API
- **Multiple Certificate Support**: Manage multiple certificates with separate API keys per certificate
- **Change Detection**: Only updates files when certificate content changes
- **Automated Actions**: Run custom commands after certificate deployment (e.g., reload web servers)
- **Systemd Integration**: Automatic scheduled execution via systemd timer
- **Flexible Configuration**: YAML-based configuration with support for multiple certificate groups
- **Multiple Output Formats**: Support for PEM, PKCS12, and JKS formats

## Requirements

- Debian 12 (or compatible Linux distribution)
- Python 3
- Python packages: `python3-requests`, `python3-yaml`
- CertWarden API access with API keys

## Installation

### Automated Installation

Run the installation script as root or with sudo:

```bash
sudo ./install.sh
```

This will:
1. Install required Python packages
2. Copy the script to `/usr/local/bin/`
3. Create configuration directory at `/etc/certwarden-deploy/`
4. Install systemd service and timer files
5. Enable and start the timer

### Manual Installation

```bash
# Install dependencies
sudo apt update
sudo apt install -y python3 python3-requests python3-yaml

# Copy script
sudo cp certwarden-deploy.py /usr/local/bin/
sudo chmod +x /usr/local/bin/certwarden-deploy.py

# Create config directory and copy config
sudo mkdir -p /etc/certwarden-deploy
sudo cp config.yaml /etc/certwarden-deploy/

# Install systemd files
sudo cp certwarden-deploy.service /etc/systemd/system/
sudo cp certwarden-deploy.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certwarden-deploy.timer
```

## Configuration

### Configuration File

Edit `/etc/certwarden-deploy/config.yaml` (or `config.yaml` for local testing):

```yaml
# Base URL of your CertWarden instance
base_url: "https://certwarden.example.com/certwarden/api"

# Global API headers
api:
  headers:
    Content-Type: "application/txt"

# Output configuration
output:
  directory: "./certificates"
  filename_template: "{cert_id}"
  extensions:
    certificate: ".crt"
    private_key: ".key"
    privatecertchain: "_privatecertchain.pem"
    privatecert: "_privatecert.pem"

# Default options
defaults:
  format: "pem"
  expiry_alert_days: 30

# Enable/disable actions
actions:
  enabled: true

# Certificate groups
certificates:
  # Example group
  production_web_servers:
    method: "individual"
    format: "pem"
    # Separate API keys for certificate and private key operations
    cert_secret: "your_cert_api_key_here"
    key_secret: "your_key_api_key_here"
    certificates:
      - "example.com"
      - "www.example.com"
    output:
      directory: "./certificates/production"
    # Optional: Run commands after deployment
    action:
      command: "cp {certificate} {private_key} /etc/nginx/ssl/ && systemctl reload nginx"
      run_on: "new_or_changed"  # Options: new, changed, new_or_changed, all
```

### Getting API Keys from CertWarden

1. Log into your CertWarden instance
2. Navigate to your certificate
3. Create separate API keys for:
   - Certificate operations (read access to certificate)
   - Private key operations (read access to private key)
4. Add these keys to your configuration file

### Action Configuration

The `action.run_on` parameter controls when commands execute:

- `new`: Only run for newly downloaded certificates
- `changed`: Only run when certificate content changes
- `new_or_changed`: Run for new certificates or when content changes (recommended)
- `all`: Run on every execution

### Filename Templates

Customize output filenames using these variables:

- `{cert_id}`: Certificate ID from CertWarden
- `{common_name}`: Certificate common name
- `{date}`: Current date in YYYYMMDD format

Example: `"{common_name}_{date}"` → `example.com_20260204`

## Usage

### Manual Execution

Process certificates from configuration:

```bash
sudo certwarden-deploy.py --config /etc/certwarden-deploy/config.yaml process
```

### Retrieve Individual Certificates

Get a specific certificate:

```bash
certwarden-deploy.py --config config.yaml certificate CERT_ID
```

Get a private key:

```bash
certwarden-deploy.py --config config.yaml privatekey CERT_ID
```

Get certificate with private key:

```bash
certwarden-deploy.py --config config.yaml privatecert CERT_ID
```

Get certificate with private key and chain:

```bash
certwarden-deploy.py --config config.yaml privatecertchain CERT_ID
```

### Systemd Management

Check timer status:

```bash
sudo systemctl status certwarden-deploy.timer
```

View next scheduled run:

```bash
sudo systemctl list-timers certwarden-deploy.timer
```

Check service logs:

```bash
sudo journalctl -u certwarden-deploy.service
```

Run service manually:

```bash
sudo systemctl start certwarden-deploy.service
```

### Schedule Configuration

The default timer (`certwarden-deploy.timer`) runs on Mondays and Thursdays at 09:00 with a randomized delay of up to 7 hours. To modify the schedule, edit `/etc/systemd/system/certwarden-deploy.timer`:

```ini
[Timer]
OnCalendar=Mon,Thu *-*-* 09:00:00
RandomizedDelaySec=7h
```

After changes, reload systemd:

```bash
sudo systemctl daemon-reload
sudo systemctl restart certwarden-deploy.timer
```

## Exit Codes

The script returns different exit codes to indicate status:

- `0`: Success - all operations completed
- `1`: Configuration or setup error
- `2`: Certificate retrieval failures
- `3`: Action command failures

## File Structure

```
/usr/local/bin/certwarden-deploy.py    # Main script
/etc/certwarden-deploy/
  └── config.yaml                       # Configuration file
/etc/systemd/system/
  ├── certwarden-deploy.service         # Systemd service
  └── certwarden-deploy.timer           # Systemd timer
```

## Security Considerations

1. **Protect Your Configuration**: The config file contains API keys. Set appropriate permissions:
   ```bash
   sudo chmod 600 /etc/certwarden-deploy/config.yaml
   sudo chown root:root /etc/certwarden-deploy/config.yaml
   ```

2. **Use Separate API Keys**: Create dedicated API keys for certificate and private key operations with minimal required permissions

3. **Keep prod.yaml Private**: Never commit production configuration files with real credentials to version control

4. **Secure Certificate Storage**: Ensure output directories have appropriate permissions for your use case

## Troubleshooting

### Check if timer is running

```bash
sudo systemctl status certwarden-deploy.timer
```

### View detailed logs

```bash
sudo journalctl -u certwarden-deploy.service -n 50
```

### Test configuration manually

```bash
sudo /usr/local/bin/certwarden-deploy.py --config /etc/certwarden-deploy/config.yaml process
```

### Common Issues

**Authentication failures**: Verify your API keys are correct and have appropriate permissions

**Connection errors**: Check that `base_url` is correct and includes the full API path (e.g., `/certwarden/api`)

**Action commands failing**: Ensure commands have appropriate permissions and all required files exist

**Files not updating**: Check that certificate content has actually changed (script only updates modified files)

## Development

### Running Locally

1. Create a local configuration file (e.g., `myconfig.yaml`)
2. Run the script:
   ```bash
   ./certwarden-deploy.py --config myconfig.yaml process
   ```

### Testing

Test individual commands without running actions:

```yaml
actions:
  enabled: false
```

## API Documentation

For more information about the CertWarden API, see:
https://www.certwarden.com/docs/using_certificates/api_calls/

## Contributing

Contributions are welcome! Please ensure:

1. Code follows existing style and conventions
2. Configuration examples use placeholder values
3. Sensitive data is never committed

## License

This project is provided as-is for use with CertWarden certificate management.

## Support

For issues with:
- **This script**: Open an issue in this repository
- **CertWarden**: Visit https://www.certwarden.com/docs/
