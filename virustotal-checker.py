import requests
import json
import os

CONFIG_FILE = 'config.json'

class VirusTotalChecker:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2/"

    def get_report(self, resource, resource_type='file'):
        """
        Get the scan report for a file or URL.
        :param resource: The hash of the file or URL to check.
        :param resource_type: 'file' or 'url', depending on the type of resource.
        :return: The JSON response from VirusTotal.
        """
        endpoint = f"{self.base_url}{resource_type}/report"
        params = {
            'apikey': self.api_key,
            'resource': resource
        }
        response = requests.get(endpoint, params=params)
        return response.json()

    def scan_file(self, file_path):
        """
        Scan a file by uploading it to VirusTotal.
        :param file_path: The path to the file to scan.
        :return: The JSON response from VirusTotal.
        """
        endpoint = f"{self.base_url}file/scan"
        files = {
            'file': (file_path, open(file_path, 'rb'))
        }
        params = {
            'apikey': self.api_key
        }
        response = requests.post(endpoint, files=files, params=params)
        return response.json()

    def scan_url(self, url):
        """
        Scan a URL.
        :param url: The URL to scan.
        :return: The JSON response from VirusTotal.
        """
        endpoint = f"{self.base_url}url/scan"
        params = {
            'apikey': self.api_key,
            'url': url
        }
        response = requests.post(endpoint, params=params)
        return response.json()

    def display_results(self, result):
        """
        Display the results in a formatted way.
        :param result: The JSON response from VirusTotal.
        """
        if result['response_code'] == 1:
            print(f"Scan Date: {result['scan_date']}")
            print(f"Permalink: {result['permalink']}")
            print(f"Positives: {result['positives']}/{result['total']}")
            print("Scans:")
            for scanner, details in result['scans'].items():
                detected = details['detected']
                result = details['result']
                print(f"  {scanner}: Detected - {detected}, Result - {result}")
        else:
            print("No results found for the given resource.")

def load_api_key():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('api_key')
        except json.JSONDecodeError:
            print("Error: The config file contains invalid JSON. Please fix or delete the file.")
    return None

def save_api_key(api_key):
    with open(CONFIG_FILE, 'w') as f:
        json.dump({'api_key': api_key}, f)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VirusTotal Checker")
    parser.add_argument("--file", help="Path to the file to scan")
    parser.add_argument("--url", help="URL to scan")
    parser.add_argument("--md5", help="MD5 hash of the file to get report")

    args = parser.parse_args()

    api_key = load_api_key()
    if not api_key:
        api_key = input("Enter your VirusTotal API key: ")
        save_api_key(api_key)

    vt_checker = VirusTotalChecker(api_key)

    if args.file:
        try:
            scan_result = vt_checker.scan_file(args.file)
            print("File scan initiated. Scan ID:", scan_result['scan_id'])
        except FileNotFoundError:
            print("File not found. Please provide a valid file path.")
    elif args.url:
        scan_result = vt_checker.scan_url(args.url)
        print("URL scan initiated. Scan ID:", scan_result['scan_id'])
    elif args.md5:
        report = vt_checker.get_report(args.md5, resource_type='file')
        vt_checker.display_results(report)
    else:
        print("Please provide a file path, URL, or MD5 hash to scan.")