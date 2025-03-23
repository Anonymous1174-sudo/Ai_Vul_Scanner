from flask import Flask, request, render_template, send_file, url_for
from scanner.web_scan import WebScanner
from scanner.network_scan import NetworkScanner

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")

        # Initialize scanners
        web_scanner = WebScanner(target)
        network_scanner = NetworkScanner(target)

        # Perform scans
        open_ports = network_scanner.scan_ports()
        vulnerabilities = web_scanner.scan_web()
        ai_report = web_scanner.analyze_results(vulnerabilities)

        # Generate report
        report_path = web_scanner.generate_pdf_report(open_ports, vulnerabilities, ai_report)

        return render_template("results.html", target=target, open_ports=open_ports, 
                               vulnerabilities=vulnerabilities, ai_report=ai_report, report_path=report_path)
    
    return render_template("index.html")

@app.route("/download/<path:filename>")
def download_report(filename):
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
