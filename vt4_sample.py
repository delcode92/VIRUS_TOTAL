import asyncio
import aiohttp
import time

# Replace with your VirusTotal API key
API_KEY = 'd8860ddc0dc6054aa98e324a3881ee5ff2a87efd9ff7d7e6978c3ecf35786308'

# The URL you want to scan
url_to_scan = 'https://diskominfo.acehprov.go.id'

# Function to submit the URL for scanning
async def submit_url_for_scanning(api_key, url):
    scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': api_key, 'url': url}
    async with aiohttp.ClientSession() as session:
        async with session.post(scan_url, data=params) as response:
            return await response.json()

# Function to retrieve the scan results
async def get_scan_results(api_key, url):
    report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': url}
    async with aiohttp.ClientSession() as session:
        async with session.get(report_url, params=params) as response:
            return await response.json()

# Function to wait for scan completion
async def wait_for_scan_completion(api_key, url, interval=30, timeout=300):
    start_time = time.time()
    while True:
        results = await get_scan_results(api_key, url)
        if results.get('response_code') == 1:
            return results
        if time.time() - start_time > timeout:
            raise TimeoutError("Scan did not complete within the timeout period.")
        await asyncio.sleep(interval)

# Main function to coordinate the tasks
async def main():
    # Submit the URL for scanning
    scan_response = await submit_url_for_scanning(API_KEY, url_to_scan)
    print(f'Scan response: {scan_response}')

    # Wait for the scan to complete and retrieve the results
    try:
        scan_results = await wait_for_scan_completion(API_KEY, url_to_scan)
        print(f'Scan results: {scan_results}')
    except TimeoutError as e:
        print(e)

# Run the main function
if __name__ == "__main__":
    asyncio.run(main())

