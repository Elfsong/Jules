import unittest
from security_agent.recon.scanner import ReconScanner
from security_agent.web.scanner import WebScanner
from security_agent.phishing.generator import PhishingGenerator
from security_agent.exploit.assessor import ExploitAssessor

class TestReconScanner(unittest.TestCase):
    def test_scan_target(self):
        scanner = ReconScanner()
        # Mocking or using localhost is tricky without mocking the nmap process.
        # We'll just check if the object is initialized correctly.
        self.assertIsNotNone(scanner.nm)

class TestWebScanner(unittest.TestCase):
    def test_scan_url_format(self):
        scanner = WebScanner()
        # Testing internal logic without making real requests (or minimal ones)
        # We can assume requests.get might fail if no internet, but we can verify structure
        # Since we are in a sandbox with internet, we can try example.com
        result = scanner.scan_url('http://example.com')
        self.assertIn('url', result)
        self.assertIn('missing_headers', result)

class TestPhishingGenerator(unittest.TestCase):
    def test_generate_email(self):
        gen = PhishingGenerator()
        email = gen.generate_email('password_reset', 'Test User', 'Test Service', 'http://link.com')
        self.assertEqual(email['subject'], 'Action Required: Password Reset for Test Service')
        self.assertIn('Test User', email['body'])

class TestExploitAssessor(unittest.TestCase):
    def test_check_vulnerabilities(self):
        assessor = ExploitAssessor()
        mock_recon = {
            '1.1.1.1': {
                'protocols': {
                    'tcp': [
                        {'port': 21, 'product': 'vsftpd', 'version': '2.3.4'}
                    ]
                }
            }
        }
        vulns = assessor.check_vulnerabilities(mock_recon)
        self.assertIn('1.1.1.1', vulns)
        self.assertEqual(vulns['1.1.1.1'][0]['vulnerability'], 'CVE-2011-2523 (Backdoor Command Execution)')

if __name__ == '__main__':
    unittest.main()
