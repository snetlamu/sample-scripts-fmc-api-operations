#!/usr/bin/env python3
"""
Cisco FMC Access Control Policy and Rules Creation Script
This script creates access control policies and generates dummy rules with variety.
Can handle thousands of rules efficiently.
"""

import requests
import json
import urllib3
from typing import List, Dict, Optional
import argparse
import logging
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import random

# Disable SSL warnings (remove in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CiscoFMCClient:
    """Cisco FMC REST API Client"""
    
    def __init__(self, server: str, username: str, password: str, domain: str = "Global"):
        """
        Initialize FMC Client
        
        Args:
            server: FMC server IP or hostname
            username: FMC username
            password: FMC password
            domain: FMC domain (default: Global)
        """
        self.server = server
        self.username = username
        self.password = password
        self.domain_name = domain
        self.base_url = f"https://{server}/api/fmc_config/v1"
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.domain_uuid = None
        self.auth_token = None
        self.refresh_token = None
        
    def authenticate(self) -> bool:
        """
        Authenticate with FMC and get access token
        
        Returns:
            bool: True if authentication successful
        """
        auth_url = f"https://{self.server}/api/fmc_platform/v1/auth/generatetoken"
        
        try:
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=False,
                timeout=30
            )
            
            if response.status_code == 204:
                self.auth_token = response.headers.get('X-auth-access-token')
                self.refresh_token = response.headers.get('X-auth-refresh-token')
                self.domain_uuid = response.headers.get('DOMAIN_UUID')
                
                # Update headers with auth token
                self.headers['X-auth-access-token'] = self.auth_token
                
                logger.info("Authentication successful")
                logger.info(f"Domain UUID: {self.domain_uuid}")
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False
    
    def create_access_policy(self, name: str, description: str = "") -> Optional[Dict]:
        """
        Create an access control policy
        
        Args:
            name: Policy name
            description: Policy description
            
        Returns:
            Policy object or None
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return None
        
        url = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies"
        
        policy_data = {
            "type": "AccessPolicy",
            "name": name,
            "description": description or f"Auto-generated policy: {name}",
            "defaultAction": {
                "action": "BLOCK",
                "logBegin": False,
                "logEnd": False,
                "sendEventsToFMC": False
            }
        }
        
        try:
            response = requests.post(
                url,
                headers=self.headers,
                data=json.dumps(policy_data),
                verify=False,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                policy = response.json()
                logger.info(f"Created access policy: {name} (ID: {policy['id']})")
                return policy
            else:
                logger.error(f"Failed to create policy: {response.status_code} - {response.text[:500]}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating policy: {str(e)}")
            return None
    
    def get_access_policy(self, name: str) -> Optional[Dict]:
        """
        Get an access control policy by name
        
        Args:
            name: Policy name
            
        Returns:
            Policy object or None
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return None
        
        url = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies"
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                for policy in data.get('items', []):
                    if policy.get('name') == name:
                        return policy
                return None
            else:
                logger.error(f"Failed to get policies: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting policy: {str(e)}")
            return None
    
    def delete_access_policy(self, policy_id: str) -> bool:
        """
        Delete an access control policy
        
        Args:
            policy_id: Policy UUID
            
        Returns:
            True if successful
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return False
        
        url = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}"
        
        try:
            response = requests.delete(
                url,
                headers=self.headers,
                verify=False,
                timeout=30
            )
            
            if response.status_code in [200, 204]:
                logger.info(f"Deleted access policy: {policy_id}")
                return True
            else:
                logger.error(f"Failed to delete policy: {response.status_code} - {response.text[:500]}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting policy: {str(e)}")
            return False
    
    def generate_access_rules(self, count: int, prefix: str = "RULE", variety: str = "mixed") -> List[Dict]:
        """
        Generate access control rule payloads with variety
        
        Args:
            count: Number of rules to generate
            prefix: Prefix for rule names
            variety: Type of variety (allow, block, mixed, complex)
            
        Returns:
            List of rule dictionaries
        """
        rules = []
        
        # Action types
        actions = ["ALLOW", "BLOCK", "TRUST", "MONITOR"]
        
        # Common source/destination IPs for realistic rules
        source_networks = [
            {"name": "any-ipv4", "value": "any"},
            {"name": "Private_10.0.0.0/8", "value": "10.0.0.0/8"},
            {"name": "Private_172.16.0.0/12", "value": "172.16.0.0/12"},
            {"name": "Private_192.168.0.0/16", "value": "192.168.0.0/16"},
        ]
        
        dest_networks = [
            {"name": "any-ipv4", "value": "any"},
            {"name": "DMZ_10.100.0.0/16", "value": "10.100.0.0/16"},
            {"name": "Servers_10.200.0.0/16", "value": "10.200.0.0/16"},
        ]
        
        # Common ports
        common_ports = [
            {"name": "HTTP", "protocol": "TCP", "port": "80"},
            {"name": "HTTPS", "protocol": "TCP", "port": "443"},
            {"name": "SSH", "protocol": "TCP", "port": "22"},
            {"name": "DNS", "protocol": "UDP", "port": "53"},
            {"name": "RDP", "protocol": "TCP", "port": "3389"},
        ]
        
        for i in range(count):
            # Determine action based on variety
            if variety == "allow":
                action = "ALLOW"
            elif variety == "block":
                action = "BLOCK"
            elif variety == "monitor":
                action = "MONITOR"
            else:  # mixed
                action = actions[i % len(actions)]
            
            # Create rule with variety
            rule = {
                "name": f"{prefix}_{i+1:04d}_{action}",
                "type": "AccessRule",
                "action": action,
                "enabled": True,
            }
            
            # Add description
            rule["description"] = f"Auto-generated {action} rule {i+1}"
            
            # Note: Complex rules with source/dest networks and ports require
            # object references (UUIDs) rather than literals. For bulk creation,
            # we keep rules simple. Use FMC UI or individual API calls with
            # proper object references for complex rules.
            
            rules.append(rule)
        
        return rules
    
    def create_access_rules_bulk(self, policy_id: str, rules: List[Dict], batch_size: int = 1000) -> Dict:
        """
        Create access control rules in bulk batches
        
        Args:
            policy_id: Access policy UUID
            rules: List of rule dictionaries
            batch_size: Number of rules per batch (FMC limit is typically 1000)
            
        Returns:
            Dictionary with creation statistics
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return {"success": 0, "failed": 0, "total": 0}
        
        url = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}/accessrules?bulk=true"
        
        total_rules = len(rules)
        success_count = 0
        failed_count = 0
        
        # Process in batches
        for batch_start in range(0, total_rules, batch_size):
            batch_end = min(batch_start + batch_size, total_rules)
            batch = rules[batch_start:batch_end]
            
            logger.info(f"Processing batch: {batch_start+1} to {batch_end} of {total_rules}")
            
            try:
                response = requests.post(
                    url,
                    headers=self.headers,
                    data=json.dumps(batch),
                    verify=False,
                    timeout=120
                )
                
                if response.status_code in [200, 201, 202]:
                    result = response.json()
                    batch_success = len(result.get('items', batch))
                    success_count += batch_success
                    logger.info(f"Batch successful: {batch_success} rules created")
                else:
                    failed_count += len(batch)
                    logger.error(f"Batch failed: {response.status_code} - {response.text[:500]}")
                    
            except Exception as e:
                failed_count += len(batch)
                logger.error(f"Batch error: {str(e)}")
        
        return {
            "success": success_count,
            "failed": failed_count,
            "total": total_rules
        }
    
    def create_access_rules_individual(self, policy_id: str, rules: List[Dict]) -> Dict:
        """
        Create access control rules individually (fallback method)
        
        Args:
            policy_id: Access policy UUID
            rules: List of rule dictionaries
            
        Returns:
            Dictionary with creation statistics
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return {"success": 0, "failed": 0, "total": 0}
        
        url = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}/accessrules"
        
        success_count = 0
        failed_count = 0
        
        for idx, rule in enumerate(rules, 1):
            try:
                response = requests.post(
                    url,
                    headers=self.headers,
                    data=json.dumps(rule),
                    verify=False,
                    timeout=30
                )
                
                if response.status_code in [200, 201]:
                    success_count += 1
                    if idx % 50 == 0:
                        logger.info(f"Progress: {idx}/{len(rules)} rules created")
                else:
                    failed_count += 1
                    
            except Exception as e:
                failed_count += 1
                logger.error(f"Error creating rule {rule['name']}: {str(e)}")
        
        return {
            "success": success_count,
            "failed": failed_count,
            "total": len(rules)
        }
    
    def get_access_rules(self, policy_id: str, prefix: str = None, limit: int = 10000) -> List[Dict]:
        """
        Get access control rules from a policy, optionally filtered by name prefix
        
        Args:
            policy_id: Access policy UUID
            prefix: Filter rules by name prefix (optional)
            limit: Maximum number of rules to retrieve
            
        Returns:
            List of rule dictionaries
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return []
        
        all_rules = []
        offset = 0
        page_limit = 1000
        
        while offset < limit:
            url = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}/accessrules"
            params = {
                'offset': offset,
                'limit': min(page_limit, limit - offset),
                'expanded': False
            }
            
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    verify=False,
                    timeout=60
                )
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    
                    if not items:
                        break
                    
                    # Filter by prefix if specified
                    if prefix:
                        filtered_items = [rule for rule in items if rule.get('name', '').startswith(prefix)]
                        all_rules.extend(filtered_items)
                    else:
                        all_rules.extend(items)
                    
                    # Check if we've retrieved all rules
                    paging = data.get('paging', {})
                    if offset + len(items) >= paging.get('count', 0):
                        break
                    
                    offset += len(items)
                    logger.info(f"Retrieved {len(all_rules)} rules so far...")
                else:
                    logger.error(f"Failed to get rules: {response.status_code} - {response.text[:500]}")
                    break
                    
            except Exception as e:
                logger.error(f"Error getting rules: {str(e)}")
                break
        
        logger.info(f"Total rules retrieved: {len(all_rules)}")
        return all_rules
    
    def delete_access_rules_bulk(self, policy_id: str, rule_ids: List[str], max_workers: int = 5, rate_limit: int = 80) -> Dict:
        """
        Delete access control rules in parallel with rate limiting
        
        Args:
            policy_id: Access policy UUID
            rule_ids: List of rule UUIDs to delete
            max_workers: Maximum number of parallel threads (default: 5)
            rate_limit: Maximum requests per minute (default: 80 for FMC)
            
        Returns:
            Dictionary with deletion statistics
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return {"success": 0, "failed": 0, "total": 0}
        
        total_rules = len(rule_ids)
        success_count = 0
        failed_count = 0
        
        # Rate limiting
        min_delay = 60.0 / rate_limit
        counter_lock = threading.Lock()
        last_request_time = [time.time() - min_delay]
        
        def delete_single_rule(rule_id: str) -> tuple:
            """Delete a single rule with rate limiting and retry logic"""
            nonlocal last_request_time
            
            max_retries = 5
            base_wait_time = 2
            
            for attempt in range(max_retries):
                # Rate limiting
                with counter_lock:
                    current_time = time.time()
                    time_since_last = current_time - last_request_time[0]
                    if time_since_last < min_delay:
                        sleep_time = min_delay - time_since_last
                        time.sleep(sleep_time)
                    last_request_time[0] = time.time()
                
                try:
                    url = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}/accessrules/{rule_id}"
                    response = requests.delete(
                        url,
                        headers=self.headers,
                        verify=False,
                        timeout=30
                    )
                    
                    if response.status_code in [200, 204]:
                        return (True, rule_id, None)
                    elif response.status_code == 429:
                        wait_time = base_wait_time * (2 ** attempt)
                        retry_after = response.headers.get('Retry-After')
                        
                        if retry_after:
                            try:
                                wait_time = max(int(retry_after), wait_time)
                            except ValueError:
                                pass
                        
                        time.sleep(wait_time)
                        continue
                    else:
                        return (False, rule_id, f"HTTP {response.status_code}")
                        
                except Exception as e:
                    if attempt < max_retries - 1:
                        wait_time = base_wait_time * (2 ** attempt)
                        time.sleep(wait_time)
                        continue
                    return (False, rule_id, str(e))
            
            return (False, rule_id, "Max retries exceeded")
        
        logger.info(f"Starting parallel deletion with {max_workers} workers (rate limit: {rate_limit} req/min)")
        logger.info(f"Minimum delay between requests: {min_delay:.3f} seconds")
        
        # Execute deletions in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_id = {executor.submit(delete_single_rule, rule_id): rule_id for rule_id in rule_ids}
            
            for future in as_completed(future_to_id):
                success, rule_id, error = future.result()
                
                if success:
                    success_count += 1
                else:
                    failed_count += 1
                
                # Log progress every 50 deletions
                total_processed = success_count + failed_count
                if total_processed % 50 == 0 or total_processed == total_rules:
                    percentage = (total_processed / total_rules) * 100
                    logger.info(f"Deletion in progress: {success_count}/{total_rules} deleted ({percentage:.1f}% complete)")
        
        return {
            "success": success_count,
            "failed": failed_count,
            "total": total_rules
        }


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Create access control policy and generate dummy rules in Cisco FMC'
    )
    parser.add_argument('-s', '--server', required=True, help='FMC server IP or hostname')
    parser.add_argument('-u', '--username', required=True, help='FMC username')
    parser.add_argument('-p', '--password', required=True, help='FMC password')
    parser.add_argument('-n', '--number', type=int, help='Number of rules to create')
    parser.add_argument('-d', '--domain', default='Global', help='FMC domain (default: Global)')
    parser.add_argument('--policy', required=True, help='Access policy name')
    parser.add_argument('--prefix', default='RULE', help='Prefix for rule names (default: RULE)')
    parser.add_argument('--variety', choices=['allow', 'block', 'monitor', 'mixed'], default='mixed',
                       help='Type of rules to generate (default: mixed)')
    parser.add_argument('--batch-size', type=int, default=1000, help='Batch size for bulk creation (default: 1000)')
    parser.add_argument('--individual', action='store_true', help='Create rules individually instead of bulk')
    parser.add_argument('--clear-rules', action='store_true', help='Delete all rules with the specified prefix')
    parser.add_argument('--delete-policy', action='store_true', help='Delete the entire policy')
    parser.add_argument('--max-workers', type=int, default=5, help='Maximum parallel threads for deletion (default: 5)')
    parser.add_argument('--rate-limit', type=int, default=80, help='Maximum requests per minute (default: 80)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.clear_rules and not args.delete_policy and not args.number:
        logger.error("Either --number, --clear-rules, or --delete-policy must be specified")
        parser.print_help()
        return
    
    if args.number and args.number <= 0:
        logger.error("Number of rules must be greater than 0")
        return
    
    if args.number and args.number > 10000:
        logger.warning("Creating more than 10,000 rules may take significant time")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            return
    
    # Initialize FMC client
    fmc = CiscoFMCClient(args.server, args.username, args.password, args.domain)
    
    # Authenticate
    if not fmc.authenticate():
        logger.error("Authentication failed. Exiting.")
        return
    
    start_time = datetime.now()
    
    # Handle delete-policy mode
    if args.delete_policy:
        logger.info("=" * 60)
        logger.info(f"DELETING ACCESS POLICY: {args.policy}")
        logger.info("=" * 60)
        
        # Confirm deletion
        response = input(f"Are you sure you want to delete policy '{args.policy}' and ALL its rules? (yes/no): ")
        if response.lower() != 'yes':
            logger.info("Deletion cancelled.")
            return
        
        # Get policy
        policy = fmc.get_access_policy(args.policy)
        if not policy:
            logger.error(f"Policy '{args.policy}' not found")
            return
        
        # Delete policy
        if fmc.delete_access_policy(policy['id']):
            logger.info(f"Successfully deleted policy '{args.policy}'")
        else:
            logger.error(f"Failed to delete policy '{args.policy}'")
        
        return
    
    # Get or create policy
    logger.info(f"Looking for access policy: {args.policy}")
    policy = fmc.get_access_policy(args.policy)
    
    if not policy:
        if args.clear_rules:
            logger.error(f"Policy '{args.policy}' not found. Cannot clear rules.")
            return
        
        logger.info(f"Policy '{args.policy}' not found. Creating new policy...")
        policy = fmc.create_access_policy(args.policy)
        
        if not policy:
            logger.error("Failed to create policy. Exiting.")
            return
    else:
        logger.info(f"Found existing policy: {args.policy} (ID: {policy['id']})")
    
    policy_id = policy['id']
    
    # Handle clear-rules mode
    if args.clear_rules:
        logger.info("=" * 60)
        logger.info(f"DELETING RULES WITH PREFIX: {args.prefix}")
        logger.info("=" * 60)
        
        # Confirm deletion
        response = input(f"Are you sure you want to delete all rules starting with '{args.prefix}' from policy '{args.policy}'? (yes/no): ")
        if response.lower() != 'yes':
            logger.info("Deletion cancelled.")
            return
        
        # Get all rules with the prefix
        logger.info(f"Retrieving all rules with prefix '{args.prefix}'...")
        rules = fmc.get_access_rules(policy_id, prefix=args.prefix)
        
        if not rules:
            logger.info(f"No rules found with prefix '{args.prefix}'")
            return
        
        logger.info(f"Found {len(rules)} rules to delete")
        
        # Extract rule IDs
        rule_ids = [rule['id'] for rule in rules if 'id' in rule]
        
        # Delete rules
        logger.info("Deleting rules in parallel...")
        stats = fmc.delete_access_rules_bulk(
            policy_id,
            rule_ids, 
            max_workers=args.max_workers,
            rate_limit=args.rate_limit
        )
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print statistics
        logger.info("=" * 60)
        logger.info("DELETION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total rules:          {stats['total']}")
        logger.info(f"Successfully deleted: {stats['success']}")
        logger.info(f"Failed:               {stats['failed']}")
        logger.info(f"Duration:             {duration:.2f} seconds")
        if stats['success'] > 0:
            logger.info(f"Rate:                 {stats['success']/duration:.2f} rules/second")
        logger.info("=" * 60)
    
    # Handle creation mode
    else:
        logger.info(f"Starting rule creation in policy: {args.policy}")
        logger.info(f"Number of rules: {args.number}")
        logger.info(f"Rule variety: {args.variety}")
        logger.info(f"Batch size: {args.batch_size}")
        
        # Generate rules
        logger.info(f"Generating {args.number} access control rules...")
        rules = fmc.generate_access_rules(args.number, args.prefix, args.variety)
        logger.info(f"Generated {len(rules)} rules")
        
        # Create rules
        logger.info("Creating rules in FMC...")
        
        if args.individual:
            stats = fmc.create_access_rules_individual(policy_id, rules)
        else:
            stats = fmc.create_access_rules_bulk(policy_id, rules, args.batch_size)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print statistics
        logger.info("=" * 60)
        logger.info("CREATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Policy:               {args.policy}")
        logger.info(f"Total rules:          {stats['total']}")
        logger.info(f"Successfully created: {stats['success']}")
        logger.info(f"Failed:               {stats['failed']}")
        logger.info(f"Duration:             {duration:.2f} seconds")
        if stats['success'] > 0:
            logger.info(f"Rate:                 {stats['success']/duration:.2f} rules/second")
        logger.info("=" * 60)


if __name__ == "__main__":
    main()
