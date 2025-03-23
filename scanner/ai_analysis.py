from transformers import pipeline

class AIAnalyzer:
    def __init__(self):
        self.model = pipeline("summarization")

    def analyze_vulnerabilities(self, open_ports, vulnerabilities):
        input_text = f"Open ports: {open_ports}. Vulnerabilities: {vulnerabilities}."
        analysis = self.model(input_text, max_length=50, min_length=10, do_sample=False)[0]['summary_text']
        return analysis
