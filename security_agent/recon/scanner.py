import nmap

class ReconScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_target(self, target, ports='1-1024'):
        """
        Scans a target for open ports and services.

        :param target: IP address or hostname to scan.
        :param ports: Range of ports to scan (default: 1-1024).
        :return: A dictionary containing scan results.
        """
        print(f"Scanning {target} on ports {ports}...")
        try:
            # -sV: Probe open ports to determine service/version info
            self.nm.scan(target, ports, arguments='-sV')
        except nmap.PortScannerError as e:
            return {'error': str(e)}
        except Exception as e:
            return {'error': f"Unexpected error: {str(e)}"}

        results = {}
        for host in self.nm.all_hosts():
            host_data = {'status': self.nm[host].state(), 'protocols': {}}
            for proto in self.nm[host].all_protocols():
                ports_data = []
                lport = self.nm[host][proto].keys()
                for port in sorted(lport):
                    service = self.nm[host][proto][port]
                    ports_data.append({
                        'port': port,
                        'state': service['state'],
                        'name': service['name'],
                        'product': service['product'],
                        'version': service['version']
                    })
                host_data['protocols'][proto] = ports_data
            results[host] = host_data

        return results

if __name__ == "__main__":
    # Example usage
    scanner = ReconScanner()
    # Scan localhost for testing purposes
    print(scanner.scan_target('127.0.0.1', '22-80'))
