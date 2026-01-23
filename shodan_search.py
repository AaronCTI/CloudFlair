import sys
import requests
import json
import os

INVALID_API_KEY = "[-] Your Shodan API key looks invalid.\n"
RATE_LIMIT = "[-] Looks like you exceeded your Shodan API limits. Exiting\n"

# Shodan API base URL
API_BASE_URL = "https://api.shodan.io"

# Enable debug mode via environment variable
DEBUG = os.environ.get('SHODAN_DEBUG', '').lower() in ('1', 'true', 'yes')


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
        error_message = error_data.get('error', 'Unknown error')

        error_msg = f"[-] Shodan API Error (HTTP {response.status_code})"
        if context:
            error_msg += f" {context}"
        error_msg += f": {error_message}\n"

        sys.stderr.write(error_msg)

        # Log full response for debugging
        _log_debug(f"Full error response: {json.dumps(error_data, indent=2)}")

    except (ValueError, KeyError):
        # If we can't parse JSON, show raw response
        error_msg = f"[-] Shodan API Error (HTTP {response.status_code})"
        if context:
            error_msg += f" {context}"
        error_msg += f": {response.text[:500]}\n"
        sys.stderr.write(error_msg)
        _log_debug(f"Raw error response: {response.text}")


def search_hosts(query, api_key, pages=2):
    """
    Search for hosts matching the given query using Shodan API.

    Args:
        query: Shodan search query string
        api_key: Shodan API key
        pages: Number of pages to retrieve (default: 2)

    Returns:
        Set of IPv4 addresses
    """
    try:
        hosts = set()
        page_num = 1

        _log_debug(f"Searching for hosts with query: {query}")

        # Search for hosts with pagination
        while page_num <= pages:
            try:
                # GET request to search endpoint
                search_url = f"{API_BASE_URL}/shodan/host/search"
                params = {
                    'key': api_key,
                    'query': query,
                    'page': page_num
                }

                _log_debug(f"Request URL: {search_url}")
                _log_debug(f"Request params: {json.dumps({k: v if k != 'key' else '***' for k, v in params.items()}, indent=2)}")

                response = requests.get(search_url, params=params, timeout=30)

                _log_debug(f"Response status: {response.status_code}")
                _log_debug(f"Response headers: {dict(response.headers)}")

                # Handle HTTP errors
                if response.status_code == 401:
                    sys.stderr.write(INVALID_API_KEY)
                    _handle_api_error(response, "Authentication failed")
                    exit(1)
                elif response.status_code == 403:
                    sys.stderr.write("[-] Access forbidden. Please check your Shodan API key.\n")
                    _handle_api_error(response, "Access forbidden")
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
                # Response structure: {"matches": [...], "total": N, ...}
                matches = data.get('matches', [])
                _log_debug(f"Found {len(matches)} matches on page {page_num}")

                if not matches:
                    _log_debug("No more matches found, stopping pagination")
                    break

                # Extract IP addresses from matches
                for match in matches:
                    ip = match.get('ip_str')
                    if ip:
                        hosts.add(ip)
                    else:
                        _log_debug(f"Warning: Could not extract IP from match: {list(match.keys()) if isinstance(match, dict) else type(match)}")

                _log_debug(f"Total hosts collected so far: {len(hosts)}")

                # Check if there are more pages
                total = data.get('total', 0)
                _log_debug(f"Total results available: {total}")

                # Shodan returns up to 100 results per page, check if we got less than 100
                if len(matches) < 100:
                    _log_debug("Less than 100 matches returned, no more pages")
                    break

                page_num += 1

            except requests.exceptions.RequestException as e:
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code == 401:
                        sys.stderr.write(INVALID_API_KEY)
                        _handle_api_error(e.response, "Authentication failed")
                        exit(1)
                    elif e.response.status_code == 403:
                        sys.stderr.write("[-] Access forbidden. Please check your Shodan API key.\n")
                        _handle_api_error(e.response, "Access forbidden")
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
            sys.stderr.write(INVALID_API_KEY)
            exit(1)
        elif '429' in error_str or 'rate limit' in error_str or 'limit' in error_str:
            sys.stderr.write(RATE_LIMIT)
            exit(1)
        else:
            # Re-raise unknown errors with context
            sys.stderr.write(f"[-] Unexpected error: {type(e).__name__}: {e}\n")
            raise


def get_certificates(domain, api_key, pages=2):
    """
    Search for SSL certificates matching the given domain using Shodan.

    Args:
        domain: Domain name to search for
        api_key: Shodan API key
        pages: Number of pages to retrieve (default: 2)

    Returns:
        Set of IPv4 addresses hosting certificates for the domain
    """
    # Build Shodan query for SSL certificates
    # ssl.cert.subject.cn:"domain.com" finds certificates with the domain in CN
    # port:443 ensures we get HTTPS services
    query = f'ssl.cert.subject.cn:"{domain}" port:443'

    _log_debug(f"Searching for certificates with query: {query}")

    # Use the search_hosts function with our SSL certificate query
    return search_hosts(query, api_key, pages)


def get_hosts_by_cert_fingerprints(domain, api_key, pages=2):
    """
    Alternative implementation that first searches for certificates, then finds hosts.
    This mirrors the Censys approach more closely.

    Args:
        domain: Domain name to search for
        api_key: Shodan API key
        pages: Number of pages to retrieve (default: 2)

    Returns:
        Set of IPv4 addresses
    """
    # For Shodan, we'll use the direct certificate search approach
    # since Shodan doesn't have separate certificate/host search like Censys
    return get_certificates(domain, api_key, pages)
