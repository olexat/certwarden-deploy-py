#!/usr/bin/env python3
"""
CertWarden API Client

This script demonstrates how to interact with the CertWarden API to fetch certificate data.
Documentation: https://www.certwarden.com/docs/using_certificates/api_calls/
"""

import requests
import json
import os
from datetime import datetime
import argparse


class CertWardenClient:
    """Client for interacting with the CertWarden API"""
    
    def __init__(self, api_key=None, base_url="https://api.certwarden.com"):
        """
        Initialize the CertWarden API client
        
        Args:
            api_key (str): API key for authentication (can also be set via CERTWARDEN_API_KEY env variable)
            base_url (str): Base URL for the API
        """
        self.api_key = api_key or os.environ.get("CERTWARDEN_API_KEY")
        if not self.api_key:
            raise ValueError("API key must be provided either directly or via CERTWARDEN_API_KEY environment variable")
        
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
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


def save_combined_certificate(certificate_data, output_dir="."):
    """
    Save combined certificate and private key to files
    
    Args:
        certificate_data (dict): Combined certificate data from API
        output_dir (str): Directory to save the files
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    cert_id = certificate_data.get("id", "unknown")
    common_name = certificate_data.get("common_name", "unknown").replace("*", "wildcard")
    
    # Sanitize filename
    safe_name = "".join(c if c.isalnum() else "_" for c in common_name)
    base_filename = f"{safe_name}_{cert_id}"
    
    # Save certificate
    if "certificate" in certificate_data:
        cert_path = os.path.join(output_dir, f"{base_filename}.crt")
        with open(cert_path, "w") as f:
            f.write(certificate_data["certificate"])
        print(f"Certificate saved to: {cert_path}")
    
    # Save private key
    if "private_key" in certificate_data:
        key_path = os.path.join(output_dir, f"{base_filename}.key")
        with open(key_path, "w") as f:
            f.write(certificate_data["private_key"])
        print(f"Private key saved to: {key_path}")
    
    # Save full chain if available
    if "chain" in certificate_data:
        chain_path = os.path.join(output_dir, f"{base_filename}_chain.pem")
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
        
        combined_path = os.path.join(output_dir, f"{base_filename}_combined.pem")
        with open(combined_path, "w") as f:
            f.write(combined)
        print(f"Combined PEM file saved to: {combined_path}")


def main():
    """Main function to run the script"""
    parser = argparse.ArgumentParser(description="CertWarden API Client")
    parser.add_argument("--api-key", help="CertWarden API key (can also be set via CERTWARDEN_API_KEY env var)")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
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
    
    args = parser.parse_args()
    
    try:
        client = CertWardenClient(api_key=args.api_key)
        
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
            response = client.get_expiring_certificates(days=args.days)
            display_certificates(response.get("certificates", []))
            print(f"\nFound {len(response.get('certificates', []))} certificates expiring in the next {args.days} days")
            
        elif args.command == "combined":
            certificate = client.get_combined_certificate(args.certificate_id, format=args.format)
            print(f"Retrieved combined certificate and key for ID: {args.certificate_id}")
            save_combined_certificate(certificate, output_dir=args.output_dir)
            
        elif args.command == "bulk-combined":
            response = client.get_bulk_combined_certificates(args.certificate_ids, format=args.format)
            certificates = response.get("certificates", [])
            print(f"Retrieved {len(certificates)} combined certificates with keys")
            
            for cert in certificates:
                save_combined_certificate(cert, output_dir=args.output_dir)
            
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

