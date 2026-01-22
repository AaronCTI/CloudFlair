import sys
import requests
import json
import os

INVALID_CREDS = "[-] Your Censys credentials look invalid.\n"
RATE_LIMIT = "[-] Looks like you exceeded your Censys account limits rate. Exiting\n"

# Censys Platform API base URL
API_BASE_URL = "https://api.platform.censys.io/v3/global"

# Enable debug mode via environment variable
DEBUG = os.environ.get('CENSYS_DEBUG', '').lower() in ('1', 'true', 'yes')


def _log_debug(message):
    """Log debug message if debug mode is enabled."""
    if DEBUG:
        sys.stderr.write(f"[DEBUG] {message}\n")


def _handle_api_error(response, context=""):
    """
    Handle API errors with detailed error messages.
    
    Args:
        response: requests.Response object
        context: Additional context string for error message
    """
    try:
        error_data = response.json()
        error_message = error_data.get('message', 'Unknown error')
        error_details = error_data.get('errors', {})
        
        error_msg = f"[-] API Error (HTTP {response.status_code})"
        if context:
            error_msg += f" {context}"
        error_msg += f": {error_message}\n"
        
        if error_details:
            error_msg += f"[-] Details: {json.dumps(error_details, indent=2)}\n"
        
        sys.stderr.write(error_msg)
        
        # Log full response for debugging
        _log_debug(f"Full error response: {json.dumps(error_data, indent=2)}")
        
    except (ValueError, KeyError):
        # If we can't parse JSON, show raw response
        error_msg = f"[-] API Error (HTTP {response.status_code})"
        if context:
            error_msg += f" {context}"
        error_msg += f": {response.text[:500]}\n"
        sys.stderr.write(error_msg)
        _log_debug(f"Raw error response: {response.text}")


def get_certificates(domain, api_token, pages=2, org_id=None) -> set:
    """
    Search for certificates matching the given domain using Censys Platform API.
    
    Args:
        domain: Domain name to search for
        api_token: Censys Personal Access Token
        pages: Number of pages to retrieve (default: 2)
        org_id: Censys Organization ID (required for Starter/Enterprise accounts)
    
    Returns:
        Set of certificate SHA256 fingerprints
    """
    try:
        # Update query syntax for Platform API with cert. prefix
        certificate_query = f"cert.names: {domain} and cert.parsed.signature.valid: true and not cert.names: cloudflaressl.com"
        
        fingerprints = set()
        page_num = 1
        
        headers = {
            'Authorization': f'Bearer {api_token}',
            'Accept': 'application/vnd.censys.api.v3.certificate.v1+json',
            'Content-Type': 'application/json'
        }
        
        # Add Organization ID header for Starter/Enterprise accounts
        if org_id:
            headers['X-Organization-ID'] = org_id
            _log_debug(f"Using Organization ID: {org_id}")
        
        _log_debug(f"Searching for certificates matching domain: {domain}")
        _log_debug(f"Query: {certificate_query}")
        
        # Search for certificates with pagination
        while page_num <= pages:
            try:
                # POST request to search endpoint with query parameters
                search_url = f"{API_BASE_URL}/search/query"
                params = {
                    'asset_type': 'certificate',
                    'per_page': 100,
                    'page': page_num
                }
                payload = {
                    'query': certificate_query
                }

                _log_debug(f"Request URL: {search_url}")
                _log_debug(f"Request params: {json.dumps(params, indent=2)}")
                _log_debug(f"Request payload: {json.dumps(payload, indent=2)}")
                _log_debug(f"Request headers: {json.dumps({k: v if k != 'Authorization' else 'Bearer ***' for k, v in headers.items()}, indent=2)}")

                response = requests.post(search_url, params=params, json=payload, headers=headers, timeout=30)
                
                _log_debug(f"Response status: {response.status_code}")
                _log_debug(f"Response headers: {dict(response.headers)}")
                
                # Handle HTTP errors comprehensively
                if response.status_code == 401:
                    sys.stderr.write(INVALID_CREDS)
                    _handle_api_error(response, "Authentication failed")
                    exit(1)
                elif response.status_code == 403:
                    sys.stderr.write("[-] You don't have permission to access this data. Please check your API Access role.\n")
                    _handle_api_error(response, "Permission denied")
                    exit(1)
                elif response.status_code == 422:
                    sys.stderr.write("[-] Invalid request parameters. This might be a query syntax error.\n")
                    _handle_api_error(response, "Validation error")
                    _log_debug(f"Query that failed: {certificate_query}")
                    exit(1)
                elif response.status_code == 429:
                    sys.stderr.write(RATE_LIMIT)
                    _handle_api_error(response, "Rate limit exceeded")
                    exit(1)
                elif not response.ok:
                    _handle_api_error(response, f"Request failed on page {page_num}")
                    response.raise_for_status()
                
                # Parse response
                try:
                    data = response.json()
                    _log_debug(f"Response data keys: {list(data.keys())}")
                except ValueError as e:
                    sys.stderr.write(f"[-] Failed to parse JSON response: {e}\n")
                    sys.stderr.write(f"[-] Response text: {response.text[:500]}\n")
                    raise
                
                # Extract results from response
                # Response structure: {"result": {"hits": [...], "total": N, ...}}
                items = []
                if 'result' in data:
                    if isinstance(data['result'], dict) and 'hits' in data['result']:
                        items = data['result']['hits']
                    elif isinstance(data['result'], list):
                        items = data['result']
                elif 'hits' in data:
                    items = data['hits']
                elif 'data' in data:
                    # Alternative response structure
                    if isinstance(data['data'], list):
                        items = data['data']
                    elif isinstance(data['data'], dict) and 'hits' in data['data']:
                        items = data['data']['hits']
                
                _log_debug(f"Found {len(items)} items on page {page_num}")
                
                if not items:
                    _log_debug("No more items found, stopping pagination")
                    break
                
                # Extract fingerprints from results
                for cert in items:
                    # Try different possible field names for fingerprint
                    fingerprint = None
                    if isinstance(cert, dict):
                        # Check common fingerprint field names
                        fingerprint = (cert.get('fingerprint_sha256') or 
                                      cert.get('fingerprint') or 
                                      cert.get('sha256') or
                                      cert.get('id'))
                        # Also check nested structures
                        if not fingerprint and 'fingerprint' in cert:
                            fp_obj = cert['fingerprint']
                            if isinstance(fp_obj, dict):
                                fingerprint = fp_obj.get('sha256') or fp_obj.get('sha256_fingerprint')
                    
                    if fingerprint:
                        fingerprints.add(fingerprint)
                    else:
                        _log_debug(f"Warning: Could not extract fingerprint from cert: {list(cert.keys()) if isinstance(cert, dict) else type(cert)}")
                
                _log_debug(f"Total fingerprints collected so far: {len(fingerprints)}")
                
                # Check if there are more pages
                total = None
                if 'result' in data and isinstance(data['result'], dict):
                    total = data['result'].get('total')
                elif 'total' in data:
                    total = data['total']
                
                if total is not None:
                    _log_debug(f"Total results available: {total}")
                
                if len(items) < 100:
                    _log_debug("Less than 100 items returned, no more pages")
                    break
                    
                page_num += 1
                
            except requests.exceptions.RequestException as e:
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 401:
                        sys.stderr.write(INVALID_CREDS)
                        _handle_api_error(e.response, "Authentication failed")
                        exit(1)
                    elif e.response.status_code == 403:
                        sys.stderr.write("[-] You don't have permission to access this data. Please check your API Access role.\n")
                        _handle_api_error(e.response, "Permission denied")
                        exit(1)
                    elif e.response.status_code == 422:
                        sys.stderr.write("[-] Invalid request parameters. This might be a query syntax error.\n")
                        _handle_api_error(e.response, "Validation error")
                        exit(1)
                    elif e.response.status_code == 429:
                        sys.stderr.write(RATE_LIMIT)
                        _handle_api_error(e.response, "Rate limit exceeded")
                        exit(1)
                    else:
                        _handle_api_error(e.response, f"Request exception on page {page_num}")
                
                # If it's the first page and we get an error, re-raise
                if page_num == 1:
                    raise
                # Otherwise, we've gotten some results, so break
                _log_debug(f"Error on page {page_num}, but we have {len(fingerprints)} fingerprints already")
                break
        
        _log_debug(f"Final fingerprint count: {len(fingerprints)}")
        return fingerprints
        
    except Exception as e:
        # Handle authentication/rate limit errors
        error_str = str(e).lower()
        if '401' in error_str or 'unauthorized' in error_str or 'authentication' in error_str:
            sys.stderr.write(INVALID_CREDS)
            exit(1)
        elif '429' in error_str or 'rate limit' in error_str or 'limit' in error_str:
            sys.stderr.write(RATE_LIMIT)
            exit(1)
        else:
            # Re-raise unknown errors with context
            sys.stderr.write(f"[-] Unexpected error: {type(e).__name__}: {e}\n")
            raise


def get_hosts(cert_fingerprints, api_token, org_id=None):
    """
    Search for hosts presenting certificates with the given fingerprints using Censys Platform API.
    
    Args:
        cert_fingerprints: List of certificate SHA256 fingerprints
        api_token: Censys Personal Access Token
        org_id: Censys Organization ID (required for Starter/Enterprise accounts)
    
    Returns:
        Set of IPv4 addresses
    """
    try:
        # Update query syntax for Platform API with host. prefix
        # Join fingerprints with commas for the IN query
        fingerprints_str = ','.join(cert_fingerprints)
        hosts_query = f"host.services.tls.certificates.leaf_data.fingerprint: {{{fingerprints_str}}}"
        
        hosts = set()
        page_num = 1
        
        headers = {
            'Authorization': f'Bearer {api_token}',
            'Accept': 'application/vnd.censys.api.v3.host.v1+json',
            'Content-Type': 'application/json'
        }
        
        # Add Organization ID header for Starter/Enterprise accounts
        if org_id:
            headers['X-Organization-ID'] = org_id
            _log_debug(f"Using Organization ID: {org_id}")
        
        _log_debug(f"Searching for hosts with {len(cert_fingerprints)} certificate fingerprints")
        _log_debug(f"Query: {hosts_query}")
        
        # Search for hosts - continue until no more results
        while True:
            try:
                # POST request to search endpoint with query parameters
                search_url = f"{API_BASE_URL}/search/query"
                params = {
                    'asset_type': 'host',
                    'per_page': 100,
                    'page': page_num
                }
                payload = {
                    'query': hosts_query
                }

                _log_debug(f"Request URL: {search_url}")
                _log_debug(f"Request params: {json.dumps(params, indent=2)}")
                _log_debug(f"Request payload: {json.dumps(payload, indent=2)}")
                _log_debug(f"Request headers: {json.dumps({k: v if k != 'Authorization' else 'Bearer ***' for k, v in headers.items()}, indent=2)}")

                response = requests.post(search_url, params=params, json=payload, headers=headers, timeout=30)
                
                _log_debug(f"Response status: {response.status_code}")
                _log_debug(f"Response headers: {dict(response.headers)}")
                
                # Handle HTTP errors comprehensively
                if response.status_code == 401:
                    sys.stderr.write(INVALID_CREDS)
                    _handle_api_error(response, "Authentication failed")
                    exit(1)
                elif response.status_code == 403:
                    sys.stderr.write("[-] You don't have permission to access this data. Please check your API Access role.\n")
                    _handle_api_error(response, "Permission denied")
                    exit(1)
                elif response.status_code == 422:
                    sys.stderr.write("[-] Invalid request parameters. This might be a query syntax error.\n")
                    _handle_api_error(response, "Validation error")
                    _log_debug(f"Query that failed: {hosts_query}")
                    exit(1)
                elif response.status_code == 429:
                    sys.stderr.write(RATE_LIMIT)
                    _handle_api_error(response, "Rate limit exceeded")
                    exit(1)
                elif not response.ok:
                    _handle_api_error(response, f"Request failed on page {page_num}")
                    response.raise_for_status()
                
                # Parse response
                try:
                    data = response.json()
                    _log_debug(f"Response data keys: {list(data.keys())}")
                except ValueError as e:
                    sys.stderr.write(f"[-] Failed to parse JSON response: {e}\n")
                    sys.stderr.write(f"[-] Response text: {response.text[:500]}\n")
                    raise
                
                # Extract results from response
                # Response structure: {"result": {"hits": [...], "total": N, ...}}
                items = []
                if 'result' in data:
                    if isinstance(data['result'], dict) and 'hits' in data['result']:
                        items = data['result']['hits']
                    elif isinstance(data['result'], list):
                        items = data['result']
                elif 'hits' in data:
                    items = data['hits']
                elif 'data' in data:
                    # Alternative response structure
                    if isinstance(data['data'], list):
                        items = data['data']
                    elif isinstance(data['data'], dict) and 'hits' in data['data']:
                        items = data['data']['hits']
                
                _log_debug(f"Found {len(items)} items on page {page_num}")
                
                if not items:
                    _log_debug("No more items found, stopping pagination")
                    break
                
                # Extract IP addresses from results
                for host in items:
                    # Try different possible field names for IP
                    ip = None
                    if isinstance(host, dict):
                        # Check common IP field names
                        ip = (host.get('ip') or 
                             host.get('ipv4') or 
                             host.get('address') or
                             host.get('id'))
                        # Also check nested structures
                        if not ip and 'ip' in host:
                            ip_obj = host['ip']
                            if isinstance(ip_obj, dict):
                                ip = ip_obj.get('ipv4') or ip_obj.get('address')
                    
                    if ip:
                        hosts.add(ip)
                    else:
                        _log_debug(f"Warning: Could not extract IP from host: {list(host.keys()) if isinstance(host, dict) else type(host)}")
                
                _log_debug(f"Total hosts collected so far: {len(hosts)}")
                
                # Check if there are more pages
                total = None
                if 'result' in data and isinstance(data['result'], dict):
                    total = data['result'].get('total')
                elif 'total' in data:
                    total = data['total']
                
                if total is not None:
                    _log_debug(f"Total results available: {total}")
                
                if len(items) < 100:
                    _log_debug("Less than 100 items returned, no more pages")
                    break
                    
                page_num += 1
                
            except requests.exceptions.RequestException as e:
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 401:
                        sys.stderr.write(INVALID_CREDS)
                        _handle_api_error(e.response, "Authentication failed")
                        exit(1)
                    elif e.response.status_code == 403:
                        sys.stderr.write("[-] You don't have permission to access this data. Please check your API Access role.\n")
                        _handle_api_error(e.response, "Permission denied")
                        exit(1)
                    elif e.response.status_code == 422:
                        sys.stderr.write("[-] Invalid request parameters. This might be a query syntax error.\n")
                        _handle_api_error(e.response, "Validation error")
                        exit(1)
                    elif e.response.status_code == 429:
                        sys.stderr.write(RATE_LIMIT)
                        _handle_api_error(e.response, "Rate limit exceeded")
                        exit(1)
                    else:
                        _handle_api_error(e.response, f"Request exception on page {page_num}")
                
                # If it's the first page and we get an error, re-raise
                if page_num == 1:
                    raise
                # Otherwise, we've gotten some results, so break
                _log_debug(f"Error on page {page_num}, but we have {len(hosts)} hosts already")
                break
        
        _log_debug(f"Final host count: {len(hosts)}")
        return hosts
        
    except Exception as e:
        # Handle authentication/rate limit errors
        error_str = str(e).lower()
        if '401' in error_str or 'unauthorized' in error_str or 'authentication' in error_str:
            sys.stderr.write(INVALID_CREDS)
            exit(1)
        elif '429' in error_str or 'rate limit' in error_str or 'limit' in error_str:
            sys.stderr.write(RATE_LIMIT)
            exit(1)
        else:
            # Re-raise unknown errors with context
            sys.stderr.write(f"[-] Unexpected error: {type(e).__name__}: {e}\n")
            raise
