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
import subprocess
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
        
        # Base URL priority: 1. explicit parameter, 2. config file, 3. default
        self.base_url = base_url
        if 'base_url' in self.config:
            self.base_url = self.config['base_url']
            
        # Default headers (will be overridden for specific API calls)
        self.headers = {
            "Content-Type": "application/json"
        }
        
        # Add additional headers from config if present
        if 'api' in self.config and 'headers' in self.config['api']:
            for key, value in self.config['api']['headers'].items():
                self.headers[key] = value
        
        # Store the default API key (if provided)
        self.default_api_key = api_key or os.environ.get("CERTWARDEN_API_KEY")
        
        # Store API keys from config (will be used for specific certificate/key operations)
        self.api_keys = {}
        if 'certificates' in self.config:
            for group_name, group_config in self.config['certificates'].items():
                for cert_name in group_config.get('certificates', []):
                    # Get certificate-specific API keys
                    cert_secret = group_config.get('cert_secret')
                    key_secret = group_config.get('key_secret')
                    
                    if cert_secret and key_secret:
                        self.api_keys[cert_name] = {
                            'cert': cert_secret,
                            'key': key_secret,
                            'combined': f"{cert_secret}.{key_secret}"  # For combined API calls
                        }
                        
    def _get_api_headers(self, certificate_id=None, operation_type=None):
        """
        Get the appropriate headers for a specific certificate and operation
        
        Args:
            certificate_id (str): ID of the certificate
            operation_type (str): Type of operation ('cert', 'key', or 'combined')
            
        Returns:
            dict: Headers with appropriate API key
        """
        headers = self.headers.copy()
        
        # Use certificate-specific API key if available
        if certificate_id and certificate_id in self.api_keys and operation_type:
            if operation_type in self.api_keys[certificate_id]:
                api_key = self.api_keys[certificate_id][operation_type]
                headers["X-API-Key"] = api_key
        # Fallback to default API key if certificate-specific key not found
        elif self.default_api_key:
            headers["X-API-Key"] = self.default_api_key
            
        return headers
        
    def get_certificate(self, certificate_id):
        """
        Retrieve a specific certificate by ID
        
        Args:
            certificate_id (str): The ID of the certificate to retrieve
            
        Returns:
            str: Certificate data in PEM format
        """
        endpoint = f"{self.base_url}/v1/download/certificates/{certificate_id}"
        headers = self._get_api_headers(certificate_id=certificate_id, operation_type='cert')
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        return response.text
        
    def get_combined_certificate(self, certificate_id, format="pem"):
        """
        Retrieve a certificate with its private key
        
        Args:
            certificate_id (str): The ID of the certificate to retrieve
            format (str): Format of the certificate/key (pem, pkcs12, jks)
            
        Returns:
            str or bytes: Combined certificate and key data in the specified format
        """
        endpoint = f"{self.base_url}/v1/download/certificates/{certificate_id}/combined"
        params = {"format": format}
        headers = self._get_api_headers(certificate_id=certificate_id, operation_type='combined')
        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        
        # For PEM format, return text
        if format.lower() == "pem":
            return response.text
        # For binary formats (pkcs12, jks), return content
        else:
            return response.content
        
    def get_private_cert_chains(self, certificate_ids=None, all_active=False, format="pem"):
        """
        Retrieve certificates with their private keys and certificate chains
        
        Args:
            certificate_ids (list, optional): List of certificate IDs to retrieve
            all_active (bool): Whether to retrieve all active certificates
            format (str): Format of the certificates/keys (pem, pkcs12, jks)
            
        Returns:
            str or bytes: Certificate chains data, either as text (PEM format) or binary
        """
        endpoint = f"{self.base_url}/v1/download/certificates/privatecertchains"
        
        data = {"format": format}
        if certificate_ids:
            data["certificate_ids"] = certificate_ids
        if all_active:
            data["all_active"] = True
        
        # Since this could be a bulk operation, we'll use the first certificate's API key if provided
        certificate_id = certificate_ids[0] if certificate_ids else None
        headers = self._get_api_headers(certificate_id=certificate_id, operation_type='combined')
        
        # Set headers for POST request
        headers["Content-Type"] = "application/json"
        
        response = requests.post(endpoint, headers=headers, json=data)
        response.raise_for_status()
        
        # The response format depends on the requested format
        if format.lower() == "pem":
            return response.text
        else:
            return response.content
    
    def get_private_key(self, certificate_id):
        """
        Retrieve the private key for a certificate
        
        Args:
            certificate_id (str): The ID of the certificate
            
        Returns:
            str: Private key data in PEM format
        """
        endpoint = f"{self.base_url}/v1/download/privatekeys/{certificate_id}"
        headers = self._get_api_headers(certificate_id=certificate_id, operation_type='key')
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        return response.text
        
    def get_private_keys(self, certificate_ids):
        """
        Retrieve multiple private keys in bulk
        
        Args:
            certificate_ids (list): List of certificate IDs
            
        Returns:
            str or bytes: Private keys data, either as text (PEM format) or binary
        """
        endpoint = f"{self.base_url}/v1/download/certificates/keys/bulk"
        data = {"certificate_ids": certificate_ids}
        
        # Since this is a bulk operation, we'll use the first certificate's key API key as a fallback
        certificate_id = certificate_ids[0] if certificate_ids else None
        headers = self._get_api_headers(certificate_id=certificate_id, operation_type='key')
        
        # Set headers for POST request
        headers["Content-Type"] = "application/json"
        
        response = requests.post(endpoint, headers=headers, json=data)
        response.raise_for_status()
        
        # The response is likely PEM format for keys, which is text
        try:
            # Try to decode as text first
            return response.text
        except UnicodeDecodeError:
            # If it's binary data, return the raw content
            return response.content
    
    def get_certificates_by_config(self, certificate_config):
        """
        Retrieve certificates based on configuration
        
        Args:
            certificate_config (dict): Certificate configuration from YAML
            
        Returns:
            list: Retrieved certificates
        """
        results = []
        
        # Process each certificate group from config
        for group_name, group_config in certificate_config.items():
            print(f"\nProcessing certificate group: {group_name}")
            
            # Determine retrieval method
            method = group_config.get('method', 'individual')
            format_type = group_config.get('format', 'pem')
            include_key = group_config.get('include_key', True)
            
            if method == 'individual':
                # Get certificates by IDs
                if 'certificates' in group_config:
                    cert_ids = group_config['certificates']
                    
                    # First, retrieve certificates
                    for cert_id in cert_ids:
                        try:
                            print(f"  Retrieving certificate {cert_id}...")
                            certificate_data = {}
                            
                            # Determine how to retrieve the certificate
                            if include_key:
                                # Get combined certificate + key
                                combined_data = self.get_combined_certificate(cert_id, format=format_type)
                                certificate_data = {
                                    'id': cert_id,
                                    'common_name': cert_id,  # Use cert_id as common_name for now
                                    'certificate': combined_data,
                                    'private_key': combined_data,  # The private key is included in the combined data
                                    'combined': combined_data
                                }
                            else:
                                # Get certificate only
                                cert_data = self.get_certificate(cert_id)
                                certificate_data = {
                                    'id': cert_id,
                                    'common_name': cert_id,  # Use cert_id as common_name for now
                                    'certificate': cert_data
                                }
                                
                            if certificate_data:
                                certificate_data['_group'] = group_name
                                certificate_data['_output'] = group_config.get('output', {})
                                results.append(certificate_data)
                            
                        except Exception as e:
                            print(f"  Error retrieving certificate {cert_id}: {e}")
                            
            elif method == 'all_active':
                # Get all active certificates
                try:
                    print(f"  Retrieving all active certificates...")
                    
                    if include_key:
                        # Get all active certificates with keys
                        certificates_data = self.get_private_cert_chains(all_active=True, format=format_type)
                    else:
                        # All active method not supported without using get_certificates
                        print(f"  Error: all_active method requires private keys to be enabled")
                        continue
                    
                    if certificates_data:
                        print(f"  Found active certificates")
                        
                        certificate_data = {
                            'id': "all_active",
                            'common_name': "all_active",
                            'certificate': certificates_data
                        }
                        
                        if include_key:
                            certificate_data['private_key'] = certificates_data
                            certificate_data['combined'] = certificates_data
                        
                        certificate_data['_group'] = group_name
                        certificate_data['_output'] = group_config.get('output', {})
                        results.append(certificate_data)
                        
                except Exception as e:
                    print(f"  Error retrieving all active certificates: {e}")
            
            # Group-specific certificates retrieved, now check if we need to fetch separate keys
            group_certificates = [c for c in results if c.get('_group') == group_name]
            
            if not include_key and group_config.get('fetch_keys', False) and group_certificates:
                # Collect certificate IDs from this group
                cert_ids = [cert.get('id') for cert in group_certificates if cert.get('id')]
                
                if cert_ids:
                    try:
                        print(f"  Fetching private keys for {len(cert_ids)} certificates...")
                        keys_data = self.get_private_keys(cert_ids)
                        
                        # In a real-world scenario, you'd need to parse the PEM blocks
                        # For simplicity, we'll add the same key data to all certificates
                        
                        for cert in group_certificates:
                            cert['private_key'] = keys_data
                            if 'certificate' in cert:
                                cert['combined'] = cert['certificate'] + "\n" + keys_data
                            print(f"  Added private key to certificate {cert.get('id')}")
                                
                    except Exception as e:
                        print(f"  Error fetching private keys: {e}")
        
        return results


def save_combined_certificate(certificate_data, output_dir=".", config=None):
    """
    Save combined certificate and private key to files
    
    Args:
        certificate_data (dict): Combined certificate data from API
        output_dir (str): Directory to save the files
        config (dict): Configuration dictionary
        
    Returns:
        dict: Information about saved files
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    cert_id = certificate_data.get("id", "unknown")
    common_name = certificate_data.get("common_name", "unknown").replace("*", "wildcard")
    
    # Use filename template from config if available
    filename_template = "{common_name}_{cert_id}"
    if config and 'output' in config and 'filename_template' in config['output']:
        filename_template = config['output']['filename_template']
    
    # Group-specific template overrides global config
    if '_output' in certificate_data and 'filename_template' in certificate_data['_output']:
        filename_template = certificate_data['_output']['filename_template']
    
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
    
    # Group-specific extensions override global config
    if '_output' in certificate_data and 'extensions' in certificate_data['_output']:
        extensions.update(certificate_data['_output']['extensions'])
    
    # Track saved files
    saved_files = {
        'certificate_id': cert_id,
        'common_name': common_name,
        'files': {}
    }
    
    # Save certificate
    if "certificate" in certificate_data:
        cert_path = os.path.join(output_dir, f"{base_filename}{extensions['certificate']}")
        with open(cert_path, "w") as f:
            f.write(certificate_data["certificate"])
        print(f"Certificate saved to: {cert_path}")
        saved_files['files']['certificate'] = cert_path
    
    # Save private key
    if "private_key" in certificate_data:
        key_path = os.path.join(output_dir, f"{base_filename}{extensions['private_key']}")
        with open(key_path, "w") as f:
            f.write(certificate_data["private_key"])
        print(f"Private key saved to: {key_path}")
        saved_files['files']['private_key'] = key_path
    
    # Save full chain if available
    if "chain" in certificate_data:
        chain_path = os.path.join(output_dir, f"{base_filename}{extensions['chain']}")
        with open(chain_path, "w") as f:
            f.write(certificate_data["chain"])
        print(f"Certificate chain saved to: {chain_path}")
        saved_files['files']['chain'] = chain_path
        
    # Save combined PEM (cert + chain + key) for convenience
    if "combined" in certificate_data:
        combined_path = os.path.join(output_dir, f"{base_filename}{extensions['combined']}")
        with open(combined_path, "w") as f:
            f.write(certificate_data["combined"])
        print(f"Combined PEM file saved to: {combined_path}")
        saved_files['files']['combined'] = combined_path
        
    return saved_files


def run_action_command(action_config, cert_info, is_new=False):
    """
    Run a command specified in the action configuration
    
    Args:
        action_config (dict): Action configuration from YAML
        cert_info (dict): Certificate information including paths to saved files
        is_new (bool): Whether this is a new certificate
        
    Returns:
        bool: Whether the command was run successfully
    """
    # Check if we should run the command
    run_on = action_config.get('run_on', 'new')
    if run_on == 'new' and not is_new:
        print(f"  Skipping action command (only runs on new certificates)")
        return False
        
    if run_on == 'all' or (run_on == 'new' and is_new):
        command = action_config.get('command')
        if not command:
            print(f"  No command specified in action config")
            return False
            
        # Replace placeholders in command
        formatted_command = command
        
        # Replace certificate placeholders
        formatted_command = formatted_command.replace("{cert_id}", cert_info.get('certificate_id', ''))
        formatted_command = formatted_command.replace("{common_name}", cert_info.get('common_name', ''))
        
        # Replace file path placeholders
        for file_type, file_path in cert_info.get('files', {}).items():
            placeholder = f"{{{file_type}}}"
            if placeholder in formatted_command:
                formatted_command = formatted_command.replace(placeholder, file_path)
        
        # Run the command
        try:
            print(f"  Running action command: {formatted_command}")
            result = subprocess.run(
                formatted_command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Check if command was successful
            if result.returncode == 0:
                print(f"  Command executed successfully")
                if result.stdout:
                    print(f"  Output: {result.stdout}")
                return True
            else:
                print(f"  Command failed with exit code {result.returncode}")
                if result.stderr:
                    print(f"  Error: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"  Error executing command: {e}")
            return False
    
    return False


def create_default_config():
    """
    Create a default configuration file
    
    Returns:
        dict: Default configuration
    """
    return {
        "base_url": "https://api.certwarden.com",
        "api": {
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
        "actions": {
            "enabled": True
        },
        "certificates": {
            "example_group": {
                "method": "individual",
                "cert_secret": "example_cert_api_key",  # Replace with your actual key
                "key_secret": "example_key_api_key",    # Replace with your actual key
                "certificates": ["cert_id_here"],
                "output": {
                    "directory": "./certificates/example"
                },
                "action": {
                    "command": "echo 'Certificate {common_name} ({cert_id}) processed' && cp {certificate} {private_key} /etc/ssl/",
                    "run_on": "new"
                }
            }
        }
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


def process_certificates_from_config(config_path=None):
    """
    Process certificates from configuration
    
    Args:
        config_path (str): Path to configuration file
        
    Returns:
        dict: Results of certificate processing
    """
    # Load configuration
    config = load_config(config_path)
    
    if 'certificates' not in config:
        print("No certificate configuration found in config file")
        return
    
    # Create client
    try:
        client = CertWardenClient(config_file=config_path)
    except Exception as e:
        print(f"Error creating CertWarden client: {e}")
        return
    
    # Check if actions are enabled
    actions_enabled = False
    
    if 'actions' in config and config['actions'].get('enabled', False):
        actions_enabled = True
        print("\nActions are enabled - commands will be run after certificate processing")
    
    # Get certificates
    certificates = client.get_certificates_by_config(config['certificates'])
    print(f"\nRetrieved {len(certificates)} certificates in total")
    
    # Track new and unchanged certificates
    new_certificates = []
    unchanged_certificates = []
    
    # Process each certificate
    for cert in certificates:
        # Get certificate info
        cert_id = cert.get('id', 'unknown')
        common_name = cert.get('common_name', 'unknown')
        
        # Process and save certificate
        is_new = True  # By default, assume certificate is new
        
        # Determine output directory
        output_dir = config.get('output', {}).get('directory', './certificates')
        
        # Override with group-specific output directory if available
        if '_output' in cert and 'directory' in cert['_output']:
            output_dir = cert['_output']['directory']
            
        # Handle path templates
        if '{group}' in output_dir:
            output_dir = output_dir.replace('{group}', cert.get('_group', 'default'))
            
        # Make sure directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate base filename to check if files exist
        filename_template = config.get('output', {}).get('filename_template', '{common_name}_{cert_id}')
        if '_output' in cert and 'filename_template' in cert['_output']:
            filename_template = cert['_output']['filename_template']
            
        filename = filename_template.format(
            common_name=common_name.replace("*", "wildcard"),
            cert_id=cert_id,
            date=datetime.now().strftime("%Y%m%d")
        )
        
        safe_name = "".join(c if c.isalnum() or c in ['_', '-', '.'] else "_" for c in filename)
        
        # Get extensions
        extensions = {
            'certificate': '.crt',
            'private_key': '.key',
            'chain': '_chain.pem',
            'combined': '_combined.pem'
        }
        
        if 'output' in config and 'extensions' in config['output']:
            extensions.update(config['output']['extensions'])
            
        if '_output' in cert and 'extensions' in cert['_output']:
            extensions.update(cert['_output']['extensions'])
            
        # Check if files exist
        existing_files = {}
        for file_type, ext in extensions.items():
            file_path = os.path.join(output_dir, f"{safe_name}{ext}")
            if os.path.exists(file_path):
                existing_files[file_type] = file_path
                
        # Determine if this is a new certificate
        if 'certificate' in existing_files and 'private_key' in existing_files:
            # Certificate files already exist
            is_new = False
            
        # Save certificate
        print(f"\nSaving certificate: {common_name} ({cert_id})")
        saved_info = save_combined_certificate(cert, output_dir=output_dir, config=config)
        
        # Add to the appropriate list
        if is_new:
            print(f"  Status: New certificate")
            new_certificates.append(saved_info)
        else:
            # For now, treat all existing certs as unchanged
            print(f"  Status: Certificate already exists")
            unchanged_certificates.append(saved_info)
        
        # Run actions if enabled
        if actions_enabled:
            # Get the certificate group
            group_name = cert.get('_group')
            
            # Check if there are actions for this group
            if group_name and 'certificates' in config and group_name in config['certificates']:
                group_config = config['certificates'][group_name]
                
                # Check if this group has an action defined
                if 'action' in group_config:
                    action_config = group_config['action']
                    print(f"  Running action for group: {group_name}")
                    run_action_command(action_config, saved_info, is_new=is_new)
            
    # Print summary
    print("\n" + "="*50)
    print("Certificate Processing Summary")
    print("="*50)
    print(f"New certificates: {len(new_certificates)}")
    print(f"Unchanged certificates: {len(unchanged_certificates)}")
    total = len(new_certificates) + len(unchanged_certificates)
    print(f"Total certificates processed: {total}")
    
    return {
        'new': new_certificates,
        'unchanged': unchanged_certificates
    }


def main():
    """Main function to run the script"""
    parser = argparse.ArgumentParser(description="CertWarden API Client")
    parser.add_argument("--api-key", help="CertWarden API key (can also be set via CERTWARDEN_API_KEY env var)")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--base-url", help="Override API base URL")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Config command for managing configuration
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_subparsers = config_parser.add_subparsers(dest="config_command", help="Config command")
    
    # Create default config command
    create_config_parser = config_subparsers.add_parser("create", help="Create default configuration file")
    create_config_parser.add_argument("--path", default="./certwarden.yaml", help="Path to save configuration file")
    
    # View current config command
    view_config_parser = config_subparsers.add_parser("view", help="View current configuration")
    
    # Add API key to config command
    add_key_parser = config_subparsers.add_parser("add-key", help="Add API key to configuration")
    add_key_parser.add_argument("api_key", help="API key to add")
    add_key_parser.add_argument("--path", default="./certwarden.yaml", help="Path to configuration file")
    
    # Process certificates from config
    process_parser = subparsers.add_parser("process", help="Process certificates from config")
    process_parser.add_argument("--config", help="Path to configuration file")
    
    # Get certificate command
    get_parser = subparsers.add_parser("get", help="Get a specific certificate")
    get_parser.add_argument("certificate_id", help="ID of the certificate to retrieve")
    get_parser.add_argument("--output-dir", default=".", help="Directory to save the certificate file")
    get_parser.add_argument("--output-file", help="Name of the output file (defaults to certificate_id.crt)")
    
    # Get private key command
    key_parser = subparsers.add_parser("key", help="Get the private key for a certificate")
    key_parser.add_argument("certificate_id", help="ID of the certificate whose key to retrieve")
    key_parser.add_argument("--output-dir", default=".", help="Directory to save the private key file")
    key_parser.add_argument("--output-file", help="Name of the output file (defaults to certificate_id.key)")
    
    # Get combined certificate (cert + key) command
    combined_parser = subparsers.add_parser("combined", help="Get certificate with private key")
    combined_parser.add_argument("certificate_id", help="ID of the certificate to retrieve")
    combined_parser.add_argument("--format", choices=["pem", "pkcs12", "jks"], default="pem", 
                               help="Format of the certificate/key")
    combined_parser.add_argument("--output-dir", default=".", help="Directory to save the certificate files")
    
    # Get private certificate chains command
    chains_parser = subparsers.add_parser("privatecertchains", help="Get certificates with private keys and chains")
    chains_parser.add_argument("--certificate-ids", nargs="*", help="IDs of certificates to retrieve")
    chains_parser.add_argument("--all-active", action="store_true", help="Retrieve all active certificates")
    chains_parser.add_argument("--format", choices=["pem", "pkcs12", "jks"], default="pem", 
                             help="Format of the certificates/keys")
    chains_parser.add_argument("--output-dir", default=".", help="Directory to save the certificate files")
    
    args = parser.parse_args()
    
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
    
    # Handle process command
    if args.command == "process":
        process_certificates_from_config(args.config)
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
            
        # Handle output directory from command args if provided
        if hasattr(args, 'output_dir') and args.output_dir != ".":
            output_dir = args.output_dir
            
        if args.command == "get":
            certificate = client.get_certificate(args.certificate_id)
            print(f"Retrieved certificate for ID: {args.certificate_id}")
            
            # Save to file
            # Determine filename            
            if hasattr(args, 'output_file') and args.output_file:
                output_file = os.path.join(output_dir, args.output_file)
            else:
                output_file = os.path.join(output_dir, f"{args.certificate_id}.crt")
                
            # Write certificate to file
            with open(output_file, "w") as f:
                f.write(certificate)
            print(f"Certificate saved to: {output_file}")
            
        elif args.command == "key":
            private_key = client.get_private_key(args.certificate_id)
            print(f"Retrieved private key for certificate ID: {args.certificate_id}")
            
            # Save to file
            # Determine filename
            if hasattr(args, 'output_file') and args.output_file:
                output_file = os.path.join(output_dir, args.output_file)
            else:
                output_file = os.path.join(output_dir, f"{args.certificate_id}.key")
                
            # Write key to file
            with open(output_file, "w") as f:
                f.write(private_key)
            print(f"Private key saved to: {output_file}")
            
        elif args.command == "combined":
            format_type = args.format if hasattr(args, 'format') else default_format
            certificate = client.get_combined_certificate(args.certificate_id, format=format_type)
            print(f"Retrieved combined certificate and key for ID: {args.certificate_id}")
            
            # Save to file
            filename = f"{args.certificate_id}"
            if format_type == "pem":
                output_file = os.path.join(output_dir, f"{filename}.pem")
                with open(output_file, "w") as f:
                    f.write(certificate)
            else:
                output_file = os.path.join(output_dir, f"{filename}.{format_type}")
                with open(output_file, "wb") as f:
                    f.write(certificate)
            print(f"Saved to: {output_file}")
            
        elif args.command == "privatecertchains":
            if not args.certificate_ids and not args.all_active:
                print("Error: Either --certificate-ids or --all-active must be specified")
                return
                
            format_type = args.format if hasattr(args, 'format') else default_format
            response = client.get_private_cert_chains(
                certificate_ids=args.certificate_ids, 
                all_active=args.all_active,
                format=format_type
            )
            
            print(f"Retrieved certificates with private keys and chains")
            
            # Save to file
            output_file = os.path.join(output_dir, f"private_cert_chains.{format_type}")
            if format_type == "pem":
                with open(output_file, "w") as f:
                    f.write(response)
            else:
                with open(output_file, "wb") as f:
                    f.write(response)
            print(f"Saved to: {output_file}")
            
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
