
# IOC Enrichment Tool

A simple Python CLI tool that checks an IP address against the AbuseIPDB API and returns its abuse confidence score, ISP, country, and report history.

## Features
- Checks IP reputation via AbuseIPDB API
- Handles invalid input and network errors gracefully
- Uses environment variables for API key (never hardcoded)

## Setup

1. Clone the repo
2. Install dependencies:pip install -r requirements.txt
3. Get a free AbuseIPDB API key: https://www.abuseipdb.com/register
4. Set it as an environment variable: export ABUSEIPDB_KEY="your_key_here"
5. Run the tool: 

## Example
Enter an ip address to check: 8.8.8.8
IP: 8.8.8.8
Abuse Score: 0
Country: US
ISP: Google LLC
Total Reports: 123

## Roadmap
- Support batch IP lookups from a file
- Add domain and file hash enrichment
- Export results to CSV/Markdown

