# CloudFlair

**Important note: CloudFlair requires a paid Censys account (Starter or Enterprise) with API credits, or a Shodan API key. Free Censys accounts do not have access to the search API endpoints required by this tool. You will need to purchase API credits or use Shodan to use this tool.**

CloudFlair is a tool to find origin servers of websites protected by CloudFlare (or CloudFront) which are publicly exposed and don't appropriately restrict network access to the relevant CDN IP ranges.

The tool uses Internet-wide scan data from [Censys](https://censys.io) to find exposed IPv4 hosts presenting an SSL certificate associated with the target's domain name. A Personal Access Token (PAT) is required and can be created in your [Censys Platform account](https://platform.censys.io/account/api).

For more detail about this common misconfiguration and how CloudFlair works, refer to the companion blog post at <https://blog.christophetd.fr/bypassing-cloudflare-using-internet-wide-scan-data/>.

Here's what CloudFlair looks like in action.

```bash
$ python cloudflair.py myvulnerable.site

[*] The target appears to be behind CloudFlare.
[*] Looking for certificates matching "myvulnerable.site" using Censys
[*] 75 certificates matching "myvulnerable.site" found.
[*] Looking for IPv4 hosts presenting these certificates...
[*] 10 IPv4 hosts presenting a certificate issued to "myvulnerable.site" were found.
  - 51.194.77.1
  - 223.172.21.75
  - 18.136.111.24
  - 127.200.220.231
  - 177.67.208.72
  - 137.67.239.174
  - 182.102.141.194
  - 8.154.231.164
  - 37.184.84.44
  - 78.25.205.83

[*] Retrieving target homepage at https://myvulnerable.site

[*] Testing candidate origin servers
  - 51.194.77.1
  - 223.172.21.75
  - 18.136.111.24
        responded with an unexpected HTTP status code 404
  - 127.200.220.231
        timed out after 3 seconds
  - 177.67.208.72
  - 137.67.239.174
  - 182.102.141.194
  - 8.154.231.164
  - 37.184.84.44
  - 78.25.205.83

[*] Found 2 likely origin servers of myvulnerable.site!
  - 177.67.208.72 (HTML content identical to myvulnerable.site)
  - 182.102.141.194 (HTML content identical to myvulnerable.site)
```

(_The IP addresses in this example have been obfuscated and replaced by randomly generated IPs_)

## Setup

1. Register an account on <https://platform.censys.io/register> and purchase API credits (Starter or Enterprise plan required)

2. Create a Personal Access Token (PAT) in your [Censys Platform account](https://platform.censys.io/account/api):
   - Go to Account Management > Personal Access Tokens
   - Click "Create New Token"
   - Copy your token and set it as an environment variable

3. Find your Organization ID:
   - Go to the [Censys Platform console](https://platform.censys.io)
   - Your Organization ID appears in the URL after `org=` (e.g., `org=12345678-91011-1213`)
   - Set it as an environment variable

```bash
$ export CENSYS_PAT=your-personal-access-token
$ export CENSYS_ORG_ID=your-organization-id
```

**Note:** Starter and Enterprise users need both:
- The **API Access role** assigned to their account
- Their **Organization ID** included in API requests (without it, requests are treated as free-tier)

4. Clone the repository

```bash
$ git clone https://github.com/christophetd/CloudFlair.git
```

5. Create a virtual env and install the dependencies

```bash
cd CloudFlair
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

6. Run CloudFlair (see [Usage](#usage) below for more detail)

```bash
python cloudflair.py myvulnerable.site
```

or for CloudFront
```bash
python cloudflair.py myvulnerable.site --cloudfront
```

For Shodan instead of Censys:
```bash
python cloudflair.py myvulnerable.site --search-engine shodan --shodan-api-key your-api-key
```

## Usage

```bash
$ python cloudflair.py --help

usage: cloudflair.py [-h] [-o OUTPUT_FILE] [--censys-pat CENSYS_PAT] [--censys-org-id CENSYS_ORG_ID] [--shodan-api-key SHODAN_API_KEY] [--search-engine {censys,shodan}] [--cloudfront] domain

positional arguments:
  domain                The domain to scan

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        A file to output likely origin servers to (default: None)
  --censys-pat CENSYS_PAT
                        Censys Personal Access Token. Can also be defined using the CENSYS_PAT environment variable (default: None)
  --censys-org-id CENSYS_ORG_ID
                        Censys Organization ID (required for Starter/Enterprise accounts). Can also be defined using the CENSYS_ORG_ID environment variable (default: None)
  --shodan-api-key SHODAN_API_KEY
                        Shodan API key. Can also be defined using the SHODAN_API_KEY environment variable. If provided, will use Shodan instead of Censys. (default: None)
  --search-engine {censys,shodan}
                        Search engine to use: censys or shodan (default: censys)
  --cloudfront          Check Cloudfront instead of CloudFlare. (default: False)
```

## Docker image

A lightweight Docker image of CloudFlair ([`christophetd/cloudflair`](https://hub.docker.com/r/christophetd/cloudflair/)) is provided. A scan can easily be instantiated using the following command.

```bash
$ docker run --rm -e CENSYS_PAT=your-personal-access-token -e CENSYS_ORG_ID=your-organization-id christophetd/cloudflair myvulnerable.site
```

You can also create a file containing the definition of the environment variables, and use the Docker `--env-file` option.

```bash
$ cat censys.env
CENSYS_PAT=your-personal-access-token
CENSYS_ORG_ID=your-organization-id

$ docker run --rm --env-file=censys.env christophetd/cloudflair myvulnerable.site
```

## Debugging

If you encounter issues with the API, you can enable debug mode to see detailed request/response information:

```bash
$ export CENSYS_DEBUG=1
$ python cloudflair.py myvulnerable.site
```

This will show the full API requests and responses to help diagnose issues.

For Shodan debugging:

```bash
$ export SHODAN_DEBUG=1
$ python cloudflair.py myvulnerable.site --search-engine shodan --shodan-api-key your-api-key
```

## Shodan Setup (Alternative to Censys)

CloudFlair also supports using Shodan as the search engine instead of Censys. Shodan provides a simpler API with different pricing and rate limits.

### Option 1: Free Shodan Account

1. Register a free account on <https://account.shodan.io/register>
2. Verify your email and complete the registration
3. Get your free API key from <https://account.shodan.io>

**Note:** Free Shodan accounts have rate limits (1 request per second, 1000 results per month) and may not have access to all features.

### Option 2: Paid Shodan Membership

For higher rate limits and more features, consider a paid Shodan membership at <https://account.shodan.io/billing>.

### Configuration

Set your Shodan API key as an environment variable:

```bash
$ export SHODAN_API_KEY=your-shodan-api-key
```

Or provide it via command line:

```bash
$ python cloudflair.py myvulnerable.site --search-engine shodan --shodan-api-key your-api-key
```

### Shodan vs Censys

- **Shodan**: Simpler API, potentially faster queries, different data coverage
- **Censys**: More detailed certificate analysis, enterprise features, higher API limits for paid accounts

## Compatibility

Tested on Python 3.6+. Uses only standard library dependencies (no external packages for HTML similarity). Feel free to [open an issue](https://github.com/christophetd/cloudflair/issues/new) if you have bug reports or questions.
