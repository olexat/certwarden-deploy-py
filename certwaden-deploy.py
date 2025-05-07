#!/usr/bin/env python3
"""
CertWarden API Client

This script demonstrates how to interact with the CertWarden API to fetch certificate data.
Documentation: https://www.certwarden.com/docs/using_certificates/api_calls/
"""

import requests
import json
import os
import yaml
import sys
from datetime import datetime
import argparse
from pathlib import Path


class CertWardenClient:
    """Client for interacting with the CertWarden API"""
    
    def __init__(self, api_key=None, base_url="https://api.certwarden.com", config_file=None):
        """
        Initialize the CertWarden API client
        
        Args:
            api_key (str): API key for authentication (can also be set via CERTWARDEN_API_KEY env variable)
            base_url (str): Base URL for the API
            config_file (str): Path to YAML config file
        """
        # Load configuration from file if provided
        self.config = {}
        if config_file:
            try:
                with open(config_file, 'r') as file:
                    self.config = yaml.safe_load(file) or {}
            except Exception as e:
                print(f"Error loading config file: {e}")
                sys.exit(1)
        
        # API key priority: 1. explicit parameter, 2. config file, 3. environment variable
        self.api_key = api_key or self.config.get('api_key') or os.environ.get("CERTWARDEN_API_KEY")
        if not self.api_key:
            raise ValueError("API key must be provided either directly, via config file, or via CERTWARDEN_API_KEY environment variable")
        
        # Base URL priority: 1. explicit parameter, 2. config file, 3. default
        self.base_url = base_url
        if 'api' in self.config and 'base_url' in self.config['api']:
            self.base_url = self.config['api']['base_url']
            
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Add additional headers from config if present
        if 'api' in self.config and 'headers' in self.config['api']:
            for key, value in self.config['api']['headers'].items():
                self.headers[key] = value
    
    def get_certificates(self, limit=100, offset=0, status=None):
        """
        Retrieve certificates from the API
        
        Args:
            limit (int): Maximum number of certificates to return
            offset (int): Number of certificates to skip
            status (str, optional): Filter by certificate status
            
        Returns:
            dict: API response containing certificate data
        """
        endpoint = f"{self.base_url}/v1/certificates"
        params = {
            "limit": limit,
            "offset": offset
        }
        
        if status:
            params["status"] = status
            
        response = requests.get(endpoint, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_certificate(self, certificate_id):
        """
        Retrieve a specific certificate by ID
        
        Args:
            certificate_id (str): The ID of the certificate to retrieve
            
        Returns:
            dict: Certificate data
        """
        endpoint = f"{self.base_url}/v1/certificates/{certificate_id}"
        response = requests.get(endpoint, headers=self.headers)
        response.raise_for_status()
        return response.json()
    
    def search_certificates(self, query):
        """
        Search for certificates matching the query
        
        Args:
            query (str): Search query
            
        Returns:
            dict: Search results
        """
        endpoint = f"{self.base_url}/v1/certificates/search"
        params = {"q": query}
        response = requests.get(endpoint, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()
    
    def create_certificate(self, certificate_data):
        """
        Create a new certificate
        
        Args:
            certificate_data (dict): Certificate information
            
        Returns:
            dict: Created certificate data
        """
        endpoint = f"{self.base_url}/v1/certificates"
        response = requests.post(endpoint, headers=self.headers, json=certificate_data)
        response.raise_for_status()
        return response.json()
    
    def revoke_certificate(self, certificate_id, reason="unspecified"):
        """
        Revoke a certificate
        
        Args:
            certificate_id (str): The ID of the certificate to revoke
            reason (str): Reason for revocation
            
        Returns:
            dict: Response data
        """
        endpoint = f"{self.base_url}/v1/certificates/{certificate_id}/revoke"
        data = {"reason": reason}
        response = requests.post(endpoint, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def get_expiring_certificates(self, days=30):
        """
        Get certificates expiring within the specified number of days
        
        Args:
            days (int): Number of days to check for expiration
            
        Returns:
            dict: Expiring certificates
        """
        endpoint = f"{self.base_url}/v1/certificates/expiring"
        params = {"days": days}
        response = requests.get(endpoint, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()
        
    def get_combined_certificate(self, certificate_id, format="pem"):
        """
        Retrieve a certificate with its private key
        
        Args:
            certificate_id (str): The ID of the certificate to retrieve
            format (str): Format of the certificate/key (pem, pkcs12, jks)
            
        Returns:
            dict: Certificate data with private key
        """
        endpoint = f"{self.base_url}/v1/certificates/{certificate_id}/combined"
        params = {"format": format}
        response = requests.get(endpoint, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_bulk_combined_certificates(self, certificate_ids, format="pem"):
        """
        Retrieve multiple certificates with their private keys
        
        Args:
            certificate_ids (list): List of certificate IDs to retrieve
            format (str): Format of the certificates/keys (pem, pkcs12, jks)
            
        Returns:
            dict: Certificates data with private keys
        """
        endpoint = f"{self.base_url}/v1/certificates/combined/bulk"
        data = {
            "certificate_ids": certificate_ids,
            "format": format
        }
        response = requests.post(endpoint, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
        
    def get_private_cert_chains(self, certificate_ids=None, all_active=False, format="pem"):
        """
        Retrieve certificates with their private keys and certificate chains
        
        Args:
            certificate_ids (list, optional): List of certificate IDs to retrieve
            all_active (bool): Whether to retrieve all active certificates
            format (str): Format of the certificates/keys (pem, pkcs12, jks)
            
        Returns:
            dict: Certificates data with private keys and chains
        """
        endpoint = f"{self.base_url}/v1/certificates/privatecertchains"
        
        data = {"format": format}
        if certificate_ids:
            data["certificate_ids"] = certificate_ids
        if all_active:
            data["all_active"] = True
            
        response = requests.post(endpoint, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()


def display_certificates(certificates):
    """
    Display certificate information in a readable format
    
    Args:
        certificates (list): List of certificate dictionaries
    """
    if not certificates:
        print("No certificates found.")
        return
        
    for cert in certificates:
        print(f"\n{'-'*50}")
        print(f"Certificate ID: {cert.get('id')}")
        print(f"Common Name: {cert.get('common_name')}")
        print(f"Status: {cert.get('status')}")
        
        # Format dates for better readability
        if "not_before" in cert:
            issued_date = datetime.fromisoformat(cert["not_before"].replace("Z", "+00:00"))
            print(f"Issued: {issued_date.strftime('%Y-%m-%d')}")
            
        if "not_after" in cert:
            expiry_date = datetime.fromisoformat(cert["not_after"].replace("Z", "+00:00"))
            print(f"Expires: {expiry_date.strftime('%Y-%m-%d')}")
            
        print(f"Issuer: {cert.get('issuer', 'N/A')}")
        
        if "sans" in cert and cert["sans"]:
            print("Subject Alternative Names:")
            for san in cert["sans"]:
                print(f"  - {san}")
        
        # Display if certificate has private key
        if "has_private_key" in cert:
            print(f"Has Private Key: {'Yes' if cert['has_private_key'] else 'No'}")
                
        print(f"{'-'*50}")


def save_combined_certificate(certificate_data, output_dir=".", config=None):
    """
    Save combined certificate and private key to files
    
    Args:
        certificate_data (dict): Combined certificate data from API
        output_dir (str): Directory to save the files
        config (dict): Configuration dictionary
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    cert_id = certificate_data.get("id", "unknown")
    common_name = certificate_data.get("common_name", "unknown").replace("*", "wildcard")
    
    # Use filename template from config if available
    filename_template = "{common_name}_{cert_id}"
    if config and 'output' in config and 'filename_template' in config['output']:
        filename_template = config['output']['filename_template']
    
    # Replace template variables
    filename = filename_template.format(
        common_name=common_name,
        cert_id=cert_id,
        date=datetime.now().strftime("%Y%m%d")
    )
    
    # Sanitize filename
    safe_name = "".join(c if c.isalnum() or c in ['_', '-', '.'] else "_" for c in filename)
    base_filename = safe_name
    
    # Get file extensions from config if available
    extensions = {
        'certificate': '.crt',
        'private_key': '.key',
        'chain': '_chain.pem',
        'combined': '_combined.pem'
    }
    
    if config and 'output' in config and 'extensions' in config['output']:
        extensions.update(config['output']['extensions'])
    
    # Save certificate
    if "certificate" in certificate_data:
        cert_path = os.path.join(output_dir, f"{base_filename}{extensions['certificate']}")
        with open(cert_path, "w") as f:
            f.write(certificate_data["certificate"])
        print(f"Certificate saved to: {cert_path}")
    
    # Save private key
    if "private_key" in certificate_data:
        key_path = os.path.join(output_dir, f"{base_filename}{extensions['private_key']}")
        with open(key_path, "w") as f:
            f.write(certificate_data["private_key"])
        print(f"Private key saved to: {key_path}")
    
    # Save full chain if available
    if "chain" in certificate_data:
        chain_path = os.path.join(output_dir, f"{base_filename}{extensions['chain']}")
        with open(chain_path, "w") as f:
            f.write(certificate_data["chain"])
        print(f"Certificate chain saved to: {chain_path}")
        
    # Save combined PEM (cert + chain + key) for convenience
    if "certificate" in certificate_data and "private_key" in certificate_data:
        combined = ""
        if "chain" in certificate_data:
            combined = certificate_data["chain"]
        else:
            combined = certificate_data["certificate"]
            
        combined += "\n" + certificate_data["private_key"]
        
        combined_path = os.path.join(output_dir, f"{base_filename}{extensions['combined']}")
        with open(combined_path, "w") as f:
            f.write(combined)
        print(f"Combined PEM file saved to: {combined_path}")


def create_default_config():
    """
    Create a default configuration file
    
    Returns:
        dict: Default configuration
    """
    return {
        "api": {
            "base_url": "https://api.certwarden.com",
            "headers": {
                "Content-Type": "application/json"
            }
        },
        "output": {
            "directory": "./certificates",
            "filename_template": "{common_name}_{cert_id}",
            "extensions": {
                "certificate": ".crt",
                "private_key": ".key",
                "chain": "_chain.pem",
                "combined": "_combined.pem"
            }
        },
        "defaults": {
            "format": "pem",
            "expiry_alert_days": 30
        },
        "certificates": []  # Array of certificate IDs to fetch
    }


def load_config(config_path=None):
    """
    Load configuration from file or create default
    
    Args:
        config_path (str): Path to config file
        
    Returns:
        dict: Configuration dictionary
    """
    if not config_path:
        # Check if config exists in default locations
        default_locations = [
            "./certwarden.yaml",
            "./certwarden.yml",
            "~/.certwarden/config.yaml",
            "~/.certwarden/config.yml",
            "/etc/certwarden/config.yaml",
            "/etc/certwarden/config.yml"
        ]
        
        for loc in default_locations:
            expanded_path = os.path.expanduser(loc)
            if os.path.exists(expanded_path):
                config_path = expanded_path
                break
    
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as file:
                config = yaml.safe_load(file) or {}
                print(f"Loaded configuration from {config_path}")
                return config
        except Exception as e:
            print(f"Error loading config file: {e}")
    
    # Return default config if no file found or error occurred
    return create_default_config()


def save_config(config, config_path):
    """
    Save configuration to file
    
    Args:
        config (dict): Configuration dictionary
        config_path (str): Path to save config file
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
        
        with open(config_path, 'w') as file:
            yaml.dump(config, file, default_flow_style=False)
            print(f"Configuration saved to {config_path}")
    except Exception as e:
        print(f"Error saving config file: {e}")


def setup_argument_parser():
    """
    Set up command line argument parser
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="CertWarden API Client",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global arguments
    parser.add_argument("--api-key", help="API key for authentication")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--base-url", help="Base URL for the API")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Config management commands
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_subparsers = config_parser.add_subparsers(dest="config_command", help="Config operation")
    
    # Create config command
    create_config_parser = config_subparsers.add_parser("create", help="Create default configuration file")
    create_config_parser.add_argument("--path", default="~/.certwarden/config.yaml", help="Path to save configuration file")
    
    # View config command
    view_config_parser = config_subparsers.add_parser("view", help="View current configuration")
    
    # Add API key to config command
    add_key_parser = config_subparsers.add_parser("add-key", help="Add API key to configuration")
    add_key_parser.add_argument("api_key", help="API key to add")
    add_key_parser.add_argument("--path", default="~/.certwarden/config.yaml", help="Path to configuration file")
    
    # Add certificate ID to config command
    add_cert_parser = config_subparsers.add_parser("add-cert", help="Add certificate ID to configuration")
    add_cert_parser.add_argument("certificate_id", help="Certificate ID to add")
    add_cert_parser.add_argument("--path", default="~/.certwarden/config.yaml", help="Path to configuration file")
    
    # List certificates command
    list_parser = subparsers.add_parser("list", help="List certificates")
    list_parser.add_argument("--limit", type=int, default=10, help="Maximum number of certificates to return")
    list_parser.add_argument("--offset", type=int, default=0, help="Number of certificates to skip")
    list_parser.add_argument("--status", help="Filter by certificate status")
    
    # Get certificate command
    get_parser = subparsers.add_parser("get", help="Get a specific certificate")
    get_parser.add_argument("certificate_id", help="ID of the certificate to retrieve")
    
    # Search certificates command
    search_parser = subparsers.add_parser("search", help="Search for certificates")
    search_parser.add_argument("query", help="Search query")
    
    # Get expiring certificates command
    expiring_parser = subparsers.add_parser("expiring", help="Get expiring certificates")
    expiring_parser.add_argument("--days", type=int, default=30, help="Number of days to check for expiration")
    
    # Get combined certificate (cert + key) command
    combined_parser = subparsers.add_parser("combined", help="Get certificate with private key")
    combined_parser.add_argument("certificate_id", help="ID of the certificate to retrieve")
    combined_parser.add_argument("--format", choices=["pem", "pkcs12", "jks"], default="pem", 
                               help="Format of the certificate/key")
    combined_parser.add_argument("--output-dir", default=".", help="Directory to save the certificate files")
    
    # Get bulk combined certificates command
    bulk_parser = subparsers.add_parser("bulk-combined", help="Get multiple certificates with private keys")
    bulk_parser.add_argument("certificate_ids", nargs="+", help="IDs of certificates to retrieve")
    bulk_parser.add_argument("--format", choices=["pem", "pkcs12", "jks"], default="pem", 
                           help="Format of the certificates/keys")
    bulk_parser.add_argument("--output-dir", default=".", help="Directory to save the certificate files")
    
    # Get private certificate chains command
    chains_parser = subparsers.add_parser("privatecertchains", help="Get certificates with private keys and chains")
    chains_parser.add_argument("--certificate-ids", nargs="*", help="IDs of certificates to retrieve")
    chains_parser.add_argument("--all-active", action="store_true", help="Retrieve all active certificates")
    chains_parser.add_argument("--from-config", action="store_true", help="Use certificate IDs from config file")
    chains_parser.add_argument("--format", choices=["pem", "pkcs12", "jks"], default="pem", 
                             help="Format of the certificates/keys")
    chains_parser.add_argument("--output-dir", default=".", help="Directory to save the certificate files")
    
    return parser


def main():
    """
    Main function for the CertWarden CLI
    """
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # If no command provided, show help
    if not args.command:
        parser.print_help()
        return
    
    # Handle config commands first
    if args.command == "config":
        if args.config_command == "create":
            config = create_default_config()
            save_config(config, args.path)
            return
        elif args.config_command == "view":
            config = load_config(args.config)
            print(yaml.dump(config, default_flow_style=False))
            return
        elif args.config_command == "add-key":
            config_path = args.path
            
            # Load existing config or create new one
            if os.path.exists(config_path):
                config = load_config(config_path)
            else:
                config = create_default_config()
            
            # Add API key
            config["api_key"] = args.api_key
            save_config(config, config_path)
            print(f"API key added to configuration")
            return
        elif args.config_command == "add-cert":
            config_path = args.path
            
            # Load existing config or create new one
            if os.path.exists(config_path):
                config = load_config(config_path)
            else:
                config = create_default_config()
            
            # Initialize certificates array if not present
            if 'certificates' not in config:
                config['certificates'] = []
            
            # Add certificate ID if not already in the list
            if args.certificate_id not in config['certificates']:
                config['certificates'].append(args.certificate_id)
                save_config(config, config_path)
                print(f"Certificate ID '{args.certificate_id}' added to configuration")
            else:
                print(f"Certificate ID '{args.certificate_id}' already in configuration")
            return
    
    # Load configuration
    config = load_config(args.config)
    
    try:
        # Override config with command line parameters if provided
        if args.base_url:
            if 'api' not in config:
                config['api'] = {}
            config['api']['base_url'] = args.base_url
            
        # Create API client with config
        client = CertWardenClient(api_key=args.api_key, config_file=args.config)
        
        # Default output directory from config
        output_dir = "."
        if 'output' in config and 'directory' in config['output']:
            output_dir = config['output']['directory']
            # Create directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
        
        # Default format from config
        default_format = "pem"
        if 'defaults' in config and 'format' in config['defaults']:
            default_format = config['defaults']['format']
            
        # Default expiry days from config
        default_expiry_days = 30
        if 'defaults' in config and 'expiry_alert_days' in config['defaults']:
            default_expiry_days = config['defaults']['expiry_alert_days']
            
        # Handle output directory from command args if provided
        if hasattr(args, 'output_dir') and args.output_dir != ".":
            output_dir = args.output_dir
            
        if args.command == "list":
            response = client.get_certificates(limit=args.limit, offset=args.offset, status=args.status)
            display_certificates(response.get("certificates", []))
            print(f"\nShowing {len(response.get('certificates', []))} of {response.get('total', 0)} certificates")
            
        elif args.command == "get":
            certificate = client.get_certificate(args.certificate_id)
            display_certificates([certificate])
            
        elif args.command == "search":
            response = client.search_certificates(args.query)
            display_certificates(response.get("certificates", []))
            print(f"\nFound {len(response.get('certificates', []))} certificates matching '{args.query}'")
            
        elif args.command == "expiring":
            days = args.days if hasattr(args, 'days') else default_expiry_days
            response = client.get_expiring_certificates(days=days)
            display_certificates(response.get("certificates", []))
            print(f"\nFound {len(response.get('certificates', []))} certificates expiring in the next {days} days")
            
        elif args.command == "combined":
            format_type = args.format if hasattr(args, 'format') else default_format
            certificate = client.get_combined_certificate(args.certificate_id, format=format_type)
            print(f"Retrieved combined certificate and key for ID: {args.certificate_id}")
            save_combined_certificate(certificate, output_dir=output_dir, config=config)
            
        elif args.command == "bulk-combined":
            format_type = args.format if hasattr(args, 'format') else default_format
            response = client.get_bulk_combined_certificates(args.certificate_ids, format=format_type)
            certificates = response.get("certificates", [])
            print(f"Retrieved {len(certificates)} combined certificates with keys")
            
            for cert in certificates:
                save_combined_certificate(cert, output_dir=output_dir, config=config)
                
        elif args.command == "privatecertchains":
            certificate_ids = args.certificate_ids
            
            # If --from-config flag is used, get certificate IDs from config
            if args.from_config:
                if 'certificates' in config and config['certificates']:
                    certificate_ids = config['certificates']
                    print(f"Using certificate IDs from config: {', '.join(certificate_ids)}")
                else:
                    print("No certificate IDs found in config file")
                    return
            
            # Error if no certificates are specified in any way
            if not certificate_ids and not args.all_active:
                print("Error: Either --certificate-ids, --all-active, or --from-config must be specified")
                return
                
            format_type = args.format if hasattr(args, 'format') else default_format
            response = client.get_private_cert_chains(
                certificate_ids=certificate_ids, 
                all_active=args.all_active,
                format=format_type
            )
            
            certificates = response.get("certificates", [])
            print(f"Retrieved {len(certificates)} certificates with private keys and chains")
            
            for cert in certificates:
                save_combined_certificate(cert, output_dir=output_dir, config=config)
            
        else:
            parser.print_help()
            
    except requests.exceptions.HTTPError as e:
        print(f"API Error: {e}")
        if hasattr(e.response, 'text'):
            print(f"Response: {e.response.text}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()


import subprocess

def execute_on_success_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Success command executed:\n{result.stdout.decode()}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing success command: {e.stderr.decode()}")

    if "on_success" in config.get("defaults", {}):
        execute_on_success_command(config["defaults"]["on_success"])
