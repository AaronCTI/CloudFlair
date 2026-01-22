import sys
import requests

INVALID_CREDS = "[-] Your Censys credentials look invalid.\n"
RATE_LIMIT = "[-] Looks like you exceeded your Censys account limits rate. Exiting\n"

# Censys Platform API base URL
API_BASE_URL = "https://api.platform.censys.io/v3/global"


def get_certificates(domain, api_token, pages=2) -> set:
    """
    Search for certificates matching the given domain using Censys Platform API.
    
    Args:
        domain: Domain name to search for
        api_token: Censys Personal Access Token
        pages: Number of pages to retrieve (default: 2)
    
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
        
        # Search for certificates with pagination
        while page_num <= pages:
            try:
                # POST request to search endpoint
                search_url = f"{API_BASE_URL}/search/query"
                payload = {
                    'q': certificate_query,
                    'asset_type': 'certificate',
                    'per_page': 100,
                    'page': page_num
                }
                
                response = requests.post(search_url, json=payload, headers=headers, timeout=30)
                
                # Handle HTTP errors
                if response.status_code == 401:
                    sys.stderr.write(INVALID_CREDS)
                    exit(1)
                elif response.status_code == 429:
                    sys.stderr.write(RATE_LIMIT)
                    exit(1)
                elif response.status_code == 403:
                    sys.stderr.write("[-] You don't have permission to access this data. Please check your API Access role.\n")
                    exit(1)
                elif not response.ok:
                    response.raise_for_status()
                
                data = response.json()
                
                # Extract results from response
                # Response structure: {"result": {"hits": [...], "total": N, ...}}
                if 'result' in data and 'hits' in data['result']:
                    items = data['result']['hits']
                elif 'hits' in data:
                    items = data['hits']
                else:
                    items = []
                
                if not items:
                    break
                
                # Extract fingerprints from results
                for cert in items:
                    # Try different possible field names for fingerprint
                    fingerprint = None
                    if isinstance(cert, dict):
                        fingerprint = cert.get('fingerprint_sha256') or cert.get('fingerprint') or cert.get('sha256')
                    
                    if fingerprint:
                        fingerprints.add(fingerprint)
                
                # Check if there are more pages
                if len(items) < 100:
                    break
                    
                page_num += 1
                
            except requests.exceptions.RequestException as e:
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 401:
                        sys.stderr.write(INVALID_CREDS)
                        exit(1)
                    elif e.response.status_code == 429:
                        sys.stderr.write(RATE_LIMIT)
                        exit(1)
                # If it's the first page and we get an error, re-raise
                if page_num == 1:
                    raise
                # Otherwise, we've gotten some results, so break
                break
        
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
            # Re-raise unknown errors
            raise


def get_hosts(cert_fingerprints, api_token):
    """
    Search for hosts presenting certificates with the given fingerprints using Censys Platform API.
    
    Args:
        cert_fingerprints: List of certificate SHA256 fingerprints
        api_token: Censys Personal Access Token
    
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
        
        # Search for hosts - continue until no more results
        while True:
            try:
                # POST request to search endpoint
                search_url = f"{API_BASE_URL}/search/query"
                payload = {
                    'q': hosts_query,
                    'asset_type': 'host',
                    'per_page': 100,
                    'page': page_num
                }
                
                response = requests.post(search_url, json=payload, headers=headers, timeout=30)
                
                # Handle HTTP errors
                if response.status_code == 401:
                    sys.stderr.write(INVALID_CREDS)
                    exit(1)
                elif response.status_code == 429:
                    sys.stderr.write(RATE_LIMIT)
                    exit(1)
                elif response.status_code == 403:
                    sys.stderr.write("[-] You don't have permission to access this data. Please check your API Access role.\n")
                    exit(1)
                elif not response.ok:
                    response.raise_for_status()
                
                data = response.json()
                
                # Extract results from response
                # Response structure: {"result": {"hits": [...], "total": N, ...}}
                if 'result' in data and 'hits' in data['result']:
                    items = data['result']['hits']
                elif 'hits' in data:
                    items = data['hits']
                else:
                    items = []
                
                if not items:
                    break
                
                # Extract IP addresses from results
                for host in items:
                    # Try different possible field names for IP
                    ip = None
                    if isinstance(host, dict):
                        ip = host.get('ip') or host.get('ipv4') or host.get('address')
                        # Also check nested structures
                        if not ip and 'services' in host:
                            # Some responses might have IP at top level
                            ip = host.get('ip')
                    
                    if ip:
                        hosts.add(ip)
                
                # Check if there are more pages
                if len(items) < 100:
                    break
                    
                page_num += 1
                
            except requests.exceptions.RequestException as e:
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 401:
                        sys.stderr.write(INVALID_CREDS)
                        exit(1)
                    elif e.response.status_code == 429:
                        sys.stderr.write(RATE_LIMIT)
                        exit(1)
                # If it's the first page and we get an error, re-raise
                if page_num == 1:
                    raise
                # Otherwise, we've gotten some results, so break
                break
        
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
            # Re-raise unknown errors
            raise
