import argparse
import json
import sys
import os

# Ensure the parent directory is in sys.path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from security_agent.recon.scanner import ReconScanner
    from security_agent.web.scanner import WebScanner
    from security_agent.phishing.generator import PhishingGenerator
    from security_agent.exploit.assessor import ExploitAssessor
    from security_agent.exploit.runner import ExploitRunner
except ImportError:
    # If running as a module, imports might work differently or fail if path isn't set
    # Fallback to local imports if the above fails (though modifying sys.path usually fixes it)
    try:
        from recon.scanner import ReconScanner
        from web.scanner import WebScanner
        from phishing.generator import PhishingGenerator
        from exploit.assessor import ExploitAssessor
        from exploit.runner import ExploitRunner
    except ImportError as e:
        print(f"Import Error: {e}")
        print("Please run from the root directory using: python3 -m security_agent.agent")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Offensive Cybersecurity Agent CLI")
    subparsers = parser.add_subparsers(dest="command", help="Module to run")

    # Recon Module
    recon_parser = subparsers.add_parser("recon", help="Network Reconnaissance")
    recon_parser.add_argument("target", help="Target IP or Hostname")
    recon_parser.add_argument("--ports", default="1-100", help="Port range (default: 1-100)")

    # Web Module
    web_parser = subparsers.add_parser("web", help="Web Application Scanning")
    web_parser.add_argument("url", help="Target URL")

    # Phishing Module
    phishing_parser = subparsers.add_parser("phishing", help="Phishing Simulation")
    phishing_parser.add_argument("template", choices=['password_reset', 'urgent_update'], help="Template type")
    phishing_parser.add_argument("target_name", help="Name of the target person")
    phishing_parser.add_argument("service", help="Impersonated service name")
    phishing_parser.add_argument("link", help="Phishing link")

    # Assess Module
    exploit_parser = subparsers.add_parser("assess", help="Vulnerability Assessment")
    exploit_parser.add_argument("target", help="Target IP to scan and assess")

    # Exploit Integration Module
    exploit_run_parser = subparsers.add_parser("exploit", help="Exploitation Framework Integration")
    exploit_run_parser.add_argument("target", help="Target IP")
    exploit_run_parser.add_argument("--service", required=True, help="Service name (e.g., vsftpd)")
    exploit_run_parser.add_argument("--version", required=True, help="Service version (e.g., 2.3.4)")


    args = parser.parse_args()

    if args.command == "recon":
        scanner = ReconScanner()
        results = scanner.scan_target(args.target, args.ports)
        print(json.dumps(results, indent=2))

    elif args.command == "web":
        scanner = WebScanner()
        results = scanner.scan_url(args.url)
        print(json.dumps(results, indent=2))

    elif args.command == "phishing":
        generator = PhishingGenerator()
        email = generator.generate_email(args.template, args.target_name, args.service, args.link)
        print(json.dumps(email, indent=2))

    elif args.command == "assess":
        print(f"[*] Running Reconnaissance on {args.target}...")
        recon_scanner = ReconScanner()
        # Scan common ports for assessment
        recon_results = recon_scanner.scan_target(args.target, "21,22,80,443,8080")

        print("[*] Analyzing results for vulnerabilities...")
        assessor = ExploitAssessor()
        vulns = assessor.check_vulnerabilities(recon_results)

        if vulns:
            print(json.dumps(vulns, indent=2))
        else:
            print("No known vulnerabilities found in the mock database for the detected services.")

    elif args.command == "exploit":
        runner = ExploitRunner()
        if runner.connect():
            exploits = runner.search_exploit(args.service, args.version)
            if exploits:
                print(f"[+] Found {len(exploits)} potential exploit(s): {exploits}")
                # For demo purposes, run the first one
                result = runner.run_exploit(exploits[0], args.target)
                print(json.dumps(result, indent=2))
            else:
                print("[-] No exploits found for this service version.")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
