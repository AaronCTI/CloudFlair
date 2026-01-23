#!/usr/bin/env python3

import dns_utils
import cloudflare_utils, cloudfront_utils
import os
import sys
import censys_search
import shodan_search
import requests
import urllib3
import difflib
import cli
import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

config = {
    'http_timeout_seconds': 3,
    'response_similarity_threshold': 0.9
}

CERT_CHUNK_SIZE = 25


def calculate_similarity(text1, text2):
    """
    Calculate structural similarity between two HTML strings using difflib.

    Args:
        text1: First HTML string to compare
        text2: Second HTML string to compare

    Returns:
        Float between 0.0 and 1.0 indicating similarity (1.0 = identical)
    """
    try:
        # Split texts into lines for comparison
        lines1 = text1.splitlines()
        lines2 = text2.splitlines()

        # Use SequenceMatcher for similarity calculation
        matcher = difflib.SequenceMatcher(None, lines1, lines2)
        similarity_ratio = matcher.ratio()

        return similarity_ratio
    except:
        return 0.0


# Returns a legitimate looking user-agent
def get_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36"
    ]
    return random.choice(user_agents)


# Removes any Cloudflare IPs from the given list
def filter_cloudflare_ips(ips):
    return [ ip for ip in ips if not cloudflare_utils.is_cloudflare_ip(ip) ]


# Removes any Cloudfront IPs from the given list
def filter_cloudfront_ips(ips):
    return [ ip for ip in ips if not cloudfront_utils.is_cloudfront_ip(ip) ]


def find_hosts(domain, censys_pat, censys_org_id, shodan_api_key, search_engine, use_cloudfront):
    if not dns_utils.is_valid_domain(domain):
        sys.stderr.write('[-] The domain "%s" looks invalid.\n' % domain)
        exit(1)

    if not use_cloudfront:
        if not cloudflare_utils.uses_cloudflare(domain):
            print('[-] The domain "%s" does not seem to be behind CloudFlare.' % domain)
            exit(0)

        print('[*] The target appears to be behind CloudFlare.')

    else:
        if not cloudfront_utils.uses_cloudfront(domain):
            print('[-] The domain "%s" does not seem to be behind CloudFront.' % domain)
            exit(0)

        print('[*] The target appears to be behind CloudFront.')

    if search_engine == 'shodan':
        print('[*] Looking for SSL certificates matching "%s" using Shodan' % domain)
        hosts = shodan_search.get_certificates(domain, shodan_api_key)
        print('[*] %d IPv4 hosts with SSL certificates matching "%s" found.' % (len(hosts), domain))
    else:  # censys
        print('[*] Looking for certificates matching "%s" using Censys' % domain)
        cert_fingerprints = censys_search.get_certificates(domain, censys_pat, org_id=censys_org_id)
        cert_fingerprints = list(cert_fingerprints)
        cert_fingerprints_count = len(cert_fingerprints)
        print('[*] %d certificates matching "%s" found.' % (cert_fingerprints_count, domain))

        if cert_fingerprints_count == 0:
            print('Exiting.')
            exit(0)

        chunking = (cert_fingerprints_count > CERT_CHUNK_SIZE)
        if chunking:
            print(f'[*] Splitting the list of certificates into chunks of {CERT_CHUNK_SIZE}.')

        print('[*] Looking for IPv4 hosts presenting these certificates...')
        hosts = set()
        for i in range(0, cert_fingerprints_count, CERT_CHUNK_SIZE):
            if chunking:
                print('[*] Processing chunk %d/%d' % (i/CERT_CHUNK_SIZE + 1, cert_fingerprints_count/CERT_CHUNK_SIZE))
            hosts.update(censys_search.get_hosts(cert_fingerprints[i:i+CERT_CHUNK_SIZE], censys_pat, org_id=censys_org_id))

        print('[*] %d IPv4 hosts presenting a certificate issued to "%s" were found.' % (len(hosts), domain))

    hosts = filter_cloudflare_ips(hosts) if not use_cloudfront else filter_cloudfront_ips(hosts)

    if len(hosts) == 0:
        print('[-] The target is most likely not vulnerable.')
        exit(0)

    return set(hosts)


def print_hosts(hosts):
    for host in hosts:
        print('  - %s' % host)
    print('')


def retrieve_original_page(domain):
    url = 'https://' + domain
    print('[*] Retrieving target homepage at %s' % url)
    try:
        headers = {'User-Agent': get_user_agent()}
        original_response = requests.get(url, timeout=config['http_timeout_seconds'], headers=headers)
    except requests.exceptions.Timeout:
        sys.stderr.write('[-] %s timed out after %d seconds.\n' % (url, config['http_timeout_seconds']))
        exit(1)
    except requests.exceptions.RequestException:
        sys.stderr.write('[-] Failed to retrieve %s\n' % url)
        exit(1)

    if original_response.status_code != 200:
        print('[-] %s responded with an unexpected HTTP status code %d' % (url, original_response.status_code))
        exit(1)

    if original_response.url != url:
        print('[*] "%s" redirected to "%s"' % (url, original_response.url))

    return original_response

def print_origins(origins):
    for origin in origins:
        print('  - %s (%s)' % (origin[0], origin[1]))

    print('')

def save_origins_to_file(origins, output_file):
    if output_file is None:
        return

    try:
        with open(output_file, 'w') as f:
            for origin in origins:
                f.write(origin[0] + '\n')
        print('[*] Wrote %d likely origins to output file %s' % (len(origins), os.path.abspath(output_file)))
    except IOError as e:
        sys.stderr.write('[-] Unable to write to output file %s : %s\n' % (output_file, e))

def find_origins(domain, candidates):
    print('\n[*] Testing candidate origin servers')
    original_response = retrieve_original_page(domain)
    host_header_value = original_response.url.replace('https://', '').split('/')[0]
    origins = []
    for host in candidates:
        try:
            print('  - %s' % host)
            url = 'https://' + host
            headers = {
                'Host': host_header_value, # only keep the TLD, without any slashes
                'User-Agent': get_user_agent()
            }
            response = requests.get(url, timeout=config['http_timeout_seconds'], headers=headers, verify=False)
        except requests.exceptions.Timeout:
            print('      timed out after %d seconds' % config['http_timeout_seconds'])
            continue
        except requests.exceptions.RequestException as e:
            print('      unable to retrieve')
            continue

        if response.status_code != 200:
            print('      responded with an unexpected HTTP status code %d' % response.status_code)
            continue

        if response.text == original_response.text:
            origins.append((host, 'HTML content identical to %s' % domain))
            continue

        if len(response.text) > 0:
            try:
                page_similarity = calculate_similarity(response.text, original_response.text)
            except:
                page_similarity = 0

            if page_similarity > config['response_similarity_threshold']:
                origins.append((host, 'HTML content is %d %% structurally similar to %s' % (round(100 *page_similarity, 2), domain)))

    return origins


def main(domain, output_file, censys_pat, censys_org_id, shodan_api_key, search_engine, use_cloudfront):
    hosts = find_hosts(domain, censys_pat, censys_org_id, shodan_api_key, search_engine, use_cloudfront)
    print_hosts(hosts)
    origins = find_origins(domain, hosts)

    if len(origins) == 0:
        print('[-] Did not find any origin server.')
        exit(0)

    print('')
    print('[*] Found %d likely origin servers of %s!' % (len(origins), domain))
    print_origins(origins)
    save_origins_to_file(origins, output_file)

if __name__ == "__main__":
    args = cli.parser.parse_args()

    censys_pat = None
    censys_org_id = None
    shodan_api_key = None
    search_engine = args.search_engine

    if 'CENSYS_PAT' in os.environ:
        censys_pat = os.environ['CENSYS_PAT']

    if 'CENSYS_ORG_ID' in os.environ:
        censys_org_id = os.environ['CENSYS_ORG_ID']

    if 'SHODAN_API_KEY' in os.environ:
        shodan_api_key = os.environ['SHODAN_API_KEY']

    if args.censys_pat:
        censys_pat = args.censys_pat

    if args.censys_org_id:
        censys_org_id = args.censys_org_id

    if args.shodan_api_key:
        shodan_api_key = args.shodan_api_key

    # Validate API keys based on search engine
    if search_engine == 'censys':
        if censys_pat is None:
            sys.stderr.write('[!] Please set your Censys Personal Access Token from your environment (CENSYS_PAT) or from the command line (--censys-pat).\n')
            exit(1)

        if censys_org_id is None:
            sys.stderr.write('[!] Please set your Censys Organization ID from your environment (CENSYS_ORG_ID) or from the command line (--censys-org-id).\n')
            sys.stderr.write('[!] Find your Organization ID at https://platform.censys.io - it appears in the URL after "org=".\n')
            exit(1)
    elif search_engine == 'shodan':
        if shodan_api_key is None:
            sys.stderr.write('[!] Please set your Shodan API key from your environment (SHODAN_API_KEY) or from the command line (--shodan-api-key).\n')
            sys.stderr.write('[!] Get your API key from https://account.shodan.io\n')
            exit(1)

    main(args.domain, args.output_file, censys_pat, censys_org_id, shodan_api_key, search_engine, args.use_cloudfront)
