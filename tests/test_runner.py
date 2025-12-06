import unittest
from security_agent.exploit.runner import ExploitRunner

class TestExploitRunner(unittest.TestCase):
    def test_connection_and_search(self):
        runner = ExploitRunner()
        self.assertTrue(runner.connect())

        exploits = runner.search_exploit('vsftpd', '2.3.4')
        self.assertIn('exploit/unix/ftp/vsftpd_234_backdoor', exploits)

        exploits_empty = runner.search_exploit('secure_server', '1.0')
        self.assertEqual(exploits_empty, [])

    def test_run_exploit(self):
        runner = ExploitRunner()
        runner.connect()
        result = runner.run_exploit('exploit/unix/ftp/vsftpd_234_backdoor', '1.2.3.4')
        self.assertEqual(result['status'], 'success')
