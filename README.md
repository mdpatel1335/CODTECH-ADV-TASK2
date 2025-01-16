# CODTECH-ADV-TASK2
# Web Application Vulnerability Scanner
# Personal information

* Name : Patel Mihir

* Company : CODTECH IT SOLUTIONS PVT.LTD

* ID : CT08DAB

* Domain : Cyber Security & Ethical Hacking

* Duration: 20th Dec 2024 To 20th Jan 2025

* Mentor : Neela Santhosh kumar

# Overview
WebScanPro is an advanced tool designed to detect common security vulnerabilities in web applications. It scans websites for several critical vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), Command Injection, Cross-Site Request Forgery (CSRF), Server-Side Request Forgery (SSRF), and more. This tool is aimed at developers, security researchers, and penetration testers looking to identify vulnerabilities and ensure the security of their web applications.


# Features
- Comprehensive Vulnerability Scanning: Detects multiple types of vulnerabilities, including SQL Injection, XSS, Command Injection, SSRF, and more.
- User-Friendly Interface: Provides an easy-to-read output with clear information about any vulnerabilities detected.
- Vulnerability Simulation: Simulates real-world attack scenarios using common payloads to test various attack vectors.
- Owner and Tool Information: Displays the tool’s name and owner on startup.
- Real-Time Scan Progress: Simulates the scanning process with a display of each vulnerability being checked.
- Scan Results: Provides a list of any detected vulnerabilities after the scan is complete.

# Requirements

To run WebScanPro, the following dependencies must be installed:

- Python 3.x
- Requests - Used to make HTTP requests to the target URL.
- BeautifulSoup (bs4) - Parses HTML content to analyze forms and other elements for security.
- Termcolor - Used for colored output to enhance user experience.
- PyFiglet - Used for generating ASCII art for displaying the tool name.

You can install the required dependencies by running the following command:

    pip install requests beautifulsoup4 termcolor pyfiglet

# Steps to Run
- Step 1: Clone the Repository
-      git clone https://github.com/mdpatel1335/CODTECH-ADV-TASK2
        cd CODTECH-ADV-TASK2

- Step 2: Install Dependencies

Make sure Python 3 is installed and then install the required libraries using pip:

    pip install requests beautifulsoup4 termcolor pyfiglet

- Step 3: Run the Tool

Run the script by executing the following command in your terminal:

    python task2.py

- Step 4: Enter Target URL

You will be prompted to enter the URL of the website you want to scan for vulnerabilities:

    Enter the target URL to scan:

Type in the URL (e.g., http://example.com) and hit Enter. The scanner will begin analyzing the website for common vulnerabilities.

- Step 5: Review Results

Once the scan is complete, the tool will provide a list of any potential vulnerabilities found on the target website. If no vulnerabilities are found, it will display:

    No common vulnerabilities found.

If vulnerabilities are detected, the tool will list them along with the corresponding URLs where they were found.

- Step 6: Exit the Tool

After reviewing the results, you can exit the program. The tool will automatically stop after completing the scan.

# Vulnerabilities Checked

The tool performs checks for the following common web vulnerabilities:

- SQL Injection: Attempts to inject malicious SQL queries to manipulate the database.
- Cross-Site Scripting (XSS): Attempts to inject JavaScript code into input fields, leading to possible client-side attacks.
- Command Injection: Attempts to inject shell commands that can be executed by the server.
- Cross-Site Request Forgery (CSRF): Detects forms that lack anti-CSRF tokens.
- Server-Side Request Forgery (SSRF): Tests if the application makes unsafe requests to internal services.
- Directory Traversal: Tests if an attacker can access sensitive files outside the intended directory.
- Insecure File Upload: Detects file upload mechanisms that could allow uploading malicious files.
- Open Redirect: Identifies URLs that could redirect users to malicious sites.
- IDOR (Insecure Direct Object Reference): Attempts to access unauthorized resources by manipulating object identifiers.
- XSSI (Cross-Site Script Inclusion): Detects if sensitive data can be exposed through script inclusion.
- HTTP Response Splitting: Checks for the possibility of splitting HTTP responses.
- Reflected File Download (RFD): Detects reflected file download vulnerabilities.


# Screenshots
![Screenshot From 2025-01-16 14-21-07](https://github.com/user-attachments/assets/849ffe93-9324-4737-bf3f-545b8deed419)
![Screenshot From 2025-01-16 14-22-03](https://github.com/user-attachments/assets/770a1e1f-b4bd-4f93-b589-bd4e361aa91f)

