#!/usr/bin/env python3
"""
Cisco FMC Bulk Port Object Creation Script
This script creates port objects in bulk using Cisco FMC REST API.
Can handle thousands of port objects efficiently with various protocols.
"""

import requests
import json
import urllib3
from typing import List, Dict
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
    
    def generate_port_objects(self, count: int, prefix: str = "PORT_OBJ", port_type: str = "mixed") -> List[Dict]:
        """
        Generate port object payloads with various protocols and ports
        
        Args:
            count: Number of port objects to generate
            prefix: Prefix for object names
            port_type: Type of ports to generate (tcp, udp, mixed, ranges)
            
        Returns:
            List of port object dictionaries
        """
        port_objects = []
        
        # Common application ports for realistic data
        common_tcp_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                           465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        common_udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 
                           1812, 1813, 4500, 5060, 5353]
        
        for i in range(count):
            port_num = (i % 64512) + 1024  # Ports 1024-65535
            
            # Determine protocol and port based on type
            if port_type == "tcp":
                protocol = "TCP"
                port = str(common_tcp_ports[i % len(common_tcp_ports)]) if i < len(common_tcp_ports) * 10 else str(port_num)
            elif port_type == "udp":
                protocol = "UDP"
                port = str(common_udp_ports[i % len(common_udp_ports)]) if i < len(common_udp_ports) * 10 else str(port_num)
            elif port_type == "ranges":
                protocol = random.choice(["TCP", "UDP"])
                start_port = 1024 + (i * 10) % 60000
                end_port = min(start_port + random.randint(5, 50), 65535)
                port = f"{start_port}-{end_port}"
            else:  # mixed
                protocol = "TCP" if i % 2 == 0 else "UDP"
                if i % 5 == 0:  # 20% ranges
                    start_port = 1024 + (i * 10) % 60000
                    end_port = min(start_port + random.randint(5, 20), 65535)
                    port = f"{start_port}-{end_port}"
                else:
                    port = str(port_num)
            
            obj = {
                "name": f"{prefix}_{protocol}_{i+1}",
                "type": "ProtocolPortObject",
                "protocol": protocol,
                "port": port,
                "description": f"Auto-generated {protocol} port object {i+1}"
            }
            port_objects.append(obj)
        
        return port_objects
    
    def create_port_objects_bulk(self, port_objects: List[Dict], batch_size: int = 1000) -> Dict:
        """
        Create port objects in bulk batches
        
        Args:
            port_objects: List of port object dictionaries
            batch_size: Number of objects per batch (FMC limit is typically 1000)
            
        Returns:
            Dictionary with creation statistics
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return {"success": 0, "failed": 0, "total": 0}
        
        url = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects?bulk=true"
        
        total_objects = len(port_objects)
        success_count = 0
        failed_count = 0
        
        # Process in batches
        for batch_start in range(0, total_objects, batch_size):
            batch_end = min(batch_start + batch_size, total_objects)
            batch = port_objects[batch_start:batch_end]
            
            logger.info(f"Processing batch: {batch_start+1} to {batch_end} of {total_objects}")
            
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
                    logger.info(f"Batch successful: {batch_success} objects created")
                else:
                    failed_count += len(batch)
                    logger.error(f"Batch failed: {response.status_code} - {response.text[:500]}")
                    
            except Exception as e:
                failed_count += len(batch)
                logger.error(f"Batch error: {str(e)}")
        
        return {
            "success": success_count,
            "failed": failed_count,
            "total": total_objects
        }
    
    def create_port_objects_individual(self, port_objects: List[Dict]) -> Dict:
        """
        Create port objects individually (fallback method)
        
        Args:
            port_objects: List of port object dictionaries
            
        Returns:
            Dictionary with creation statistics
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return {"success": 0, "failed": 0, "total": 0}
        
        url = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects"
        
        success_count = 0
        failed_count = 0
        
        for idx, obj in enumerate(port_objects, 1):
            try:
                response = requests.post(
                    url,
                    headers=self.headers,
                    data=json.dumps(obj),
                    verify=False,
                    timeout=30
                )
                
                if response.status_code in [200, 201]:
                    success_count += 1
                    if idx % 100 == 0:
                        logger.info(f"Progress: {idx}/{len(port_objects)} objects created")
                else:
                    failed_count += 1
                    logger.warning(f"Failed to create {obj['name']}: {response.status_code}")
                    
            except Exception as e:
                failed_count += 1
                logger.error(f"Error creating {obj['name']}: {str(e)}")
        
        return {
            "success": success_count,
            "failed": failed_count,
            "total": len(port_objects)
        }
    
    def get_port_objects(self, prefix: str = None, limit: int = 10000) -> List[Dict]:
        """
        Get port objects from FMC, optionally filtered by name prefix
        
        Args:
            prefix: Filter objects by name prefix (optional)
            limit: Maximum number of objects to retrieve
            
        Returns:
            List of port object dictionaries
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return []
        
        all_objects = []
        offset = 0
        page_limit = 1000  # FMC page size limit
        
        while offset < limit:
            url = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects"
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
                        filtered_items = [obj for obj in items if obj.get('name', '').startswith(prefix)]
                        all_objects.extend(filtered_items)
                    else:
                        all_objects.extend(items)
                    
                    # Check if we've retrieved all objects
                    paging = data.get('paging', {})
                    if offset + len(items) >= paging.get('count', 0):
                        break
                    
                    offset += len(items)
                    logger.info(f"Retrieved {len(all_objects)} objects so far...")
                else:
                    logger.error(f"Failed to get objects: {response.status_code} - {response.text[:500]}")
                    break
                    
            except Exception as e:
                logger.error(f"Error getting objects: {str(e)}")
                break
        
        logger.info(f"Total objects retrieved: {len(all_objects)}")
        return all_objects
    
    def delete_port_objects_bulk(self, object_ids: List[str], max_workers: int = 5, rate_limit: int = 80) -> Dict:
        """
        Delete port objects in parallel with rate limiting
        
        Args:
            object_ids: List of object UUIDs to delete
            max_workers: Maximum number of parallel threads (default: 5)
            rate_limit: Maximum requests per minute (default: 80 for FMC)
            
        Returns:
            Dictionary with deletion statistics
        """
        if not self.auth_token:
            logger.error("Not authenticated. Call authenticate() first.")
            return {"success": 0, "failed": 0, "total": 0}
        
        total_objects = len(object_ids)
        success_count = 0
        failed_count = 0
        
        # Rate limiting: calculate delay between requests to stay under rate limit
        min_delay = 60.0 / rate_limit
        
        # Thread-safe counters and lock for rate limiting
        counter_lock = threading.Lock()
        last_request_time = [time.time() - min_delay]
        
        def delete_single_object(obj_id: str) -> tuple:
            """Delete a single port object with rate limiting and retry logic"""
            nonlocal last_request_time
            
            max_retries = 5
            base_wait_time = 2
            
            for attempt in range(max_retries):
                # Rate limiting: ensure minimum delay between requests
                with counter_lock:
                    current_time = time.time()
                    time_since_last = current_time - last_request_time[0]
                    if time_since_last < min_delay:
                        sleep_time = min_delay - time_since_last
                        time.sleep(sleep_time)
                    last_request_time[0] = time.time()
                
                try:
                    url = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects/{obj_id}"
                    response = requests.delete(
                        url,
                        headers=self.headers,
                        verify=False,
                        timeout=30
                    )
                    
                    if response.status_code in [200, 204]:
                        return (True, obj_id, None)
                    elif response.status_code == 429:
                        # Rate limit exceeded - use exponential backoff (silent retry)
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
                        return (False, obj_id, f"HTTP {response.status_code}")
                        
                except Exception as e:
                    if attempt < max_retries - 1:
                        wait_time = base_wait_time * (2 ** attempt)
                        time.sleep(wait_time)
                        continue
                    return (False, obj_id, str(e))
            
            return (False, obj_id, "Max retries exceeded")
        
        logger.info(f"Starting parallel deletion with {max_workers} workers (rate limit: {rate_limit} req/min)")
        logger.info(f"Minimum delay between requests: {min_delay:.3f} seconds")
        
        # Execute deletions in parallel with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all deletion tasks
            future_to_id = {executor.submit(delete_single_object, obj_id): obj_id for obj_id in object_ids}
            
            # Process completed tasks as they finish
            for future in as_completed(future_to_id):
                success, obj_id, error = future.result()
                
                if success:
                    success_count += 1
                else:
                    failed_count += 1
                
                # Log progress every 50 deletions
                total_processed = success_count + failed_count
                if total_processed % 50 == 0 or total_processed == total_objects:
                    percentage = (total_processed / total_objects) * 100
                    logger.info(f"Deletion in progress: {success_count}/{total_objects} deleted ({percentage:.1f}% complete)")
        
        return {
            "success": success_count,
            "failed": failed_count,
            "total": total_objects
        }


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Bulk create port objects in Cisco FMC using REST API'
    )
    parser.add_argument('-s', '--server', required=True, help='FMC server IP or hostname')
    parser.add_argument('-u', '--username', required=True, help='FMC username')
    parser.add_argument('-p', '--password', required=True, help='FMC password')
    parser.add_argument('-n', '--number', type=int, help='Number of objects to create')
    parser.add_argument('-d', '--domain', default='Global', help='FMC domain (default: Global)')
    parser.add_argument('--prefix', default='PORT_OBJ', help='Prefix for object names (default: PORT_OBJ)')
    parser.add_argument('--port-type', choices=['tcp', 'udp', 'mixed', 'ranges'], default='mixed',
                       help='Type of ports to generate: tcp, udp, mixed, or ranges (default: mixed)')
    parser.add_argument('--batch-size', type=int, default=1000, help='Batch size for bulk creation (default: 1000)')
    parser.add_argument('--individual', action='store_true', help='Create objects individually instead of bulk')
    parser.add_argument('--clear-all', action='store_true', help='Delete all port objects with the specified prefix')
    parser.add_argument('--max-workers', type=int, default=5, help='Maximum parallel threads for deletion (default: 5)')
    parser.add_argument('--rate-limit', type=int, default=80, help='Maximum requests per minute (default: 80, conservative for FMC)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.clear_all and not args.number:
        logger.error("Either --number or --clear-all must be specified")
        parser.print_help()
        return
    
    if args.number and args.number <= 0:
        logger.error("Number of objects must be greater than 0")
        return
    
    if args.number and args.number > 100000:
        logger.warning("Creating more than 100,000 objects may take significant time")
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
    
    # Handle clear-all mode
    if args.clear_all:
        logger.info("=" * 60)
        logger.info(f"DELETING ALL PORT OBJECTS WITH PREFIX: {args.prefix}")
        logger.info("=" * 60)
        
        # Confirm deletion
        response = input(f"Are you sure you want to delete all port objects starting with '{args.prefix}'? (yes/no): ")
        if response.lower() != 'yes':
            logger.info("Deletion cancelled.")
            return
        
        # Get all objects with the prefix
        logger.info(f"Retrieving all port objects with prefix '{args.prefix}'...")
        objects = fmc.get_port_objects(prefix=args.prefix)
        
        if not objects:
            logger.info(f"No port objects found with prefix '{args.prefix}'")
            return
        
        logger.info(f"Found {len(objects)} port objects to delete")
        
        # Extract object IDs
        object_ids = [obj['id'] for obj in objects if 'id' in obj]
        
        # Delete objects
        logger.info("Deleting port objects in parallel...")
        stats = fmc.delete_port_objects_bulk(
            object_ids, 
            max_workers=args.max_workers,
            rate_limit=args.rate_limit
        )
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print statistics
        logger.info("=" * 60)
        logger.info("DELETION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total objects:        {stats['total']}")
        logger.info(f"Successfully deleted: {stats['success']}")
        logger.info(f"Failed:               {stats['failed']}")
        logger.info(f"Duration:             {duration:.2f} seconds")
        if stats['success'] > 0:
            logger.info(f"Rate:                 {stats['success']/duration:.2f} objects/second")
        logger.info("=" * 60)
    
    # Handle creation mode
    else:
        logger.info(f"Starting bulk port object creation")
        logger.info(f"Server: {args.server}")
        logger.info(f"Number of objects: {args.number}")
        logger.info(f"Port type: {args.port_type}")
        logger.info(f"Batch size: {args.batch_size}")
        
        # Generate port objects
        logger.info(f"Generating {args.number} port objects...")
        port_objects = fmc.generate_port_objects(args.number, args.prefix, args.port_type)
        logger.info(f"Generated {len(port_objects)} port objects")
        
        # Create objects
        logger.info("Creating port objects in FMC...")
        
        if args.individual:
            stats = fmc.create_port_objects_individual(port_objects)
        else:
            stats = fmc.create_port_objects_bulk(port_objects, args.batch_size)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print statistics
        logger.info("=" * 60)
        logger.info("CREATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total objects:        {stats['total']}")
        logger.info(f"Successfully created: {stats['success']}")
        logger.info(f"Failed:               {stats['failed']}")
        logger.info(f"Duration:             {duration:.2f} seconds")
        if stats['success'] > 0:
            logger.info(f"Rate:                 {stats['success']/duration:.2f} objects/second")
        logger.info("=" * 60)


if __name__ == "__main__":
    main()
