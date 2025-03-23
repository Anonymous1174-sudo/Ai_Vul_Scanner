import requests
from bs4 import BeautifulSoup
import pdfkit

class WebScanner:
    def __init__(self, target):
        self.target = target

    def scan_web(self):
        vulnerabilities = []
        try:
            response = requests.get(self.target, timeout=5)
            if "sql" in response.text.lower():
                vulnerabilities.append("Possible SQL Injection detected.")
            if "<script>" in response.text.lower():
                vulnerabilities.append("Potential XSS vulnerability found.")

            # Check for forms (potential injection points)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            if forms:
                vulnerabilities.append(f"Found {len(forms)} form(s) that may be vulnerable.")

        except requests.RequestException:
            vulnerabilities.append("Failed to scan target.")
        
        return vulnerabilities

    def analyze_results(self, vulnerabilities):
        if not vulnerabilities:
            return "No critical vulnerabilities detected. Your website appears secure."
        
        return "\n".join([f"- {vuln}" for vuln in vulnerabilities])



    def generate_pdf_report(self, open_ports, vulnerabilities, ai_report):
        report_content = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #121212;
                color: #ffffff;
                padding: 20px;
                line-height: 1.6;
            }}
            h1, h2 {{
                color: #00bcd4;
                border-bottom: 2px solid #00bcd4;
                padding-bottom: 5px;
            }}
            .section {{
                background-color: #1e1e1e;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 15px;
                box-shadow: 0 4px 8px rgba(0, 255, 255, 0.2);
            }}
            ul {{
                list-style-type: none;
                padding: 0;
            }}
            li {{
                background-color: #2a2a2a;
                padding: 10px;
                border-radius: 5px;
                margin: 5px 0;
                border-left: 4px solid #00bcd4;
            }}
            p {{
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <h1>AI-Powered Security Scan Report</h1>
        <div class="section">
            <h2>Target: {self.target}</h2>
        </div>
        <div class="section">
            <h2>Open Ports</h2>
            <ul>{"".join(f"<li>Port {port} - Open</li>" for port in open_ports) if open_ports else "<li>No open ports detected.</li>"}</ul>
        </div>
        <div class="section">
            <h2>Vulnerabilities</h2>
            <ul>{"".join(f"<li>{vuln}</li>" for vuln in vulnerabilities) if vulnerabilities else "<li>No vulnerabilities found.</li>"}</ul>
        </div>
        <div class="section">
            <h2>AI Analysis</h2>
            <p>{ai_report}</p>
        </div>
    </body>
    </html>
    """
    
        config = pdfkit.configuration(wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")
        report_path = "scan_report.pdf"
        pdfkit.from_string(report_content, report_path, configuration=config)
        return report_path
