import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class WebScanner:
    def __init__(self):
        self.headers_to_check = [
            'X-Frame-Options',
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]

    def scan_url(self, url):
        """
        Scans a URL for common security misconfigurations.

        :param url: The URL to scan (e.g., http://example.com).
        :return: A dictionary containing scan results.
        """
        if not url.startswith('http'):
            url = 'http://' + url

        results = {
            'url': url,
            'missing_headers': [],
            'headers_present': {},
            'robots_txt': None,
            'forms_found': 0
        }

        try:
            response = requests.get(url, timeout=10)

            # Check Headers
            for header in self.headers_to_check:
                if header in response.headers:
                    results['headers_present'][header] = response.headers[header]
                else:
                    results['missing_headers'].append(header)

            # Check robots.txt
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            robots_url = f"{base_url}/robots.txt"
            try:
                robots_response = requests.get(robots_url, timeout=5)
                if robots_response.status_code == 200:
                    results['robots_txt'] = "Found"
                else:
                    results['robots_txt'] = f"Not Found (Status: {robots_response.status_code})"
            except requests.RequestException:
                results['robots_txt'] = "Error checking"

            # Check for Forms (Basic)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            results['forms_found'] = len(forms)

        except requests.RequestException as e:
            results['error'] = str(e)

        return results

if __name__ == "__main__":
    scanner = WebScanner()
    # Test with a known site (using example.com or google.com as a safe target)
    print(scanner.scan_url('http://example.com'))
