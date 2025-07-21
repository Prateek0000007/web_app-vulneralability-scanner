# web_app-vulneralability-scanner
Web Vulnerability Scanner
A Python-based web application vulnerability scanner with a command-line interface (CLI) inspired web UI. This tool helps identify common web vulnerabilities like Cross-Site Scripting (XSS), SQL Injection (SQLi), Command Injection, Path Traversal, LDAP Injection, NoSQL Injection, Sensitive Data Exposure, and Clickjacking.

🚀 Features
CLI-Inspired Web UI: A unique user interface designed to mimic a command-line terminal, providing an "ethical hacking" aesthetic.

Concurrent Scanning: Utilizes ThreadPoolExecutor to perform multiple requests simultaneously, speeding up the scanning process.

Basic Crawler: Discovers links and forms within the target domain up to a defined depth.

Vulnerability Detection:

Cross-Site Scripting (XSS): Injects various XSS payloads and checks for reflection in the response.

SQL Injection (SQLi): Injects SQLi payloads and looks for database error messages or behavioral changes.

Command Injection: Injects OS command payloads and checks for command output.

Path Traversal (Directory Traversal): Injects path traversal payloads and checks for sensitive file content.

LDAP Injection: Injects LDAP payloads and checks for LDAP-specific error messages.

NoSQL Injection: Injects NoSQL (MongoDB-like) payloads and checks for related errors or behavioral changes.

Sensitive Data Exposure: Scans page content for patterns of sensitive information (e.g., credit card numbers, API keys, passwords).

Clickjacking: Checks HTTP headers (X-Frame-Options, Content-Security-Policy) for protection against UI redressing attacks.

Cross-Site Request Forgery (CSRF): Basic check for the absence of common CSRF tokens in forms.

Dynamic Results Display: Presents scan findings in an organized, color-coded format directly in the web UI.

Red Alert Notification: A prominent red alert appears if any vulnerabilities are detected.

Robust Error Handling: Includes comprehensive try-except blocks for network errors and HTTP issues.

Basic Rate Limiting: Introduces a small delay between requests to avoid overwhelming the target server.

URL Normalization: Prevents redundant scans by normalizing URLs (e.g., sorting query parameters, removing fragments).

🛠️ Technologies Used
Python 3.x

Flask: Web framework for the backend.

Requests: HTTP library for making web requests.

BeautifulSoup4: HTML parsing library for web crawling and form/link extraction.

Concurrent.futures: For managing thread-based concurrency.

HTML/CSS/JavaScript: For the interactive CLI-inspired frontend.

Tailwind CSS: For rapid UI styling.

Roboto Mono Font: For the terminal aesthetic.

⚙️ Setup Instructions
To get this project up and running locally, follow these steps:

Clone the repository:

git clone https://github.com/your-username/web-vulnerability-scanner.git
cd web-vulnerability-scanner

(Note: Replace your-username/web-vulnerability-scanner.git with the actual repository URL if you fork it.)

Create a virtual environment (recommended):

python -m venv venv

Activate the virtual environment:

On Windows:

.\venv\Scripts\activate

On macOS/Linux:

source venv/bin/activate

Install dependencies:

pip install Flask requests beautifulsoup4

🚀 How to Run
Ensure your virtual environment is activated.

Run the Flask application:

python app.py

You should see output similar to this:

 * Serving Flask app 'app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: XXX-XXX-XXX

💻 How to Use
Open your web browser and navigate to http://127.0.0.1:5000/.

You will see the CLI-inspired web interface.

Enter the target URL you wish to scan in the input field (e.g., http://testphp.vulnweb.com/ or your local vulnerable application like http://localhost:3000/ for OWASP Juice Shop).

IMPORTANT: Only scan websites you have explicit permission to test. Using this tool on unauthorized targets is illegal and unethical.

Click the INITIATE SCAN button.

The scanner will start crawling and testing the target. Progress messages will appear in your terminal (where app.py is running), and scan results will be displayed dynamically in the web UI.

If vulnerabilities are found, a "CRITICAL VULNERABILITIES DETECTED!" alert will appear, and detailed logs will be shown below.


💡 Future Enhancements
Integration with a headless browser (e.g., Selenium, Playwright) for dynamic content scanning.

Support for authenticated scanning (login, session management).

More comprehensive and context-aware payload generation.

Advanced vulnerability detection techniques (e.g., blind SQLi timing analysis, out-of-band interaction).

Detailed reporting features (e.g., PDF, JSON export).

Integration with a database for storing scan history and results.

A more sophisticated crawling mechanism.

User-configurable scan parameters via the UI.

📄 License
This project is open-source and available under the MIT License.
(Note: You might want to create a LICENSE file in your repository with the full MIT License text.)
