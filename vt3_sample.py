import requests
import time

# Replace with your VirusTotal API key
API_KEY = 'd8860ddc0dc6054aa98e324a3881ee5ff2a87efd9ff7d7e6978c3ecf35786308'

# The URL you want to scan
url_to_scan = 'https://diskominfo.acehprov.go.id'

# Function to submit the URL for scanning
def submit_url_for_scanning(api_key, url):
    scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': api_key, 'url': url}
    response = requests.post(scan_url, data=params)
    return response.json()

# Function to retrieve the scan results
def get_scan_results(api_key, url):
    report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': url}
    response = requests.get(report_url, params=params)
    return response.json()

# Submit the URL for scanning
scan_response = submit_url_for_scanning(API_KEY, url_to_scan)
print(f'Scan response: {scan_response}')

# Wait for a short period to allow the scan to complete
time.sleep(30)  # Adjust the sleep time based on your needs

# Retrieve the scan results
scan_results = get_scan_results(API_KEY, url_to_scan)
print(f'Scan results: {scan_results}')

