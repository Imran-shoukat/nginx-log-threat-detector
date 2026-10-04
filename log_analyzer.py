import re
import random
import pandas as pd
from datetime import datetime, timedelta

# ==========================================
# 1. GENERATE MOCK LOG DATA (Built-in)
# ==========================================
def generate_mock_logs(filename="server_access.log", num_lines=200):
    ips = ["192.168.1.50", "10.0.0.12", "172.16.254.1", "45.33.22.11", "185.220.101.5"]
    methods = ["GET", "POST", "PUT", "DELETE"]
    paths = ["/index.html", "/login.php", "/api/v1/users", "/dashboard", "/assets/style.css"]
    status_codes = [200, 201, 302, 404, 500]
    
    # Malicious injection payloads for our simulator
    sqli_payloads = ["/products?id=1%20OR%201=1", "/search?q=' UNION SELECT NULL--"]
    xss_payloads = ["/comment?text=<script>alert(1)</script>", "/profile?name=%3Cscript%3E"]

    start_time = datetime.now() - timedelta(days=1)

    print(f"[*] Generating {num_lines} realistic log lines inside '{filename}'...")
    with open(filename, "w") as f:
        for i in range(num_lines):
            ip = random.choice(ips)
            method = random.choice(methods)
            status = random.choice(status_codes)
            size = random.randint(200, 5000)
            timestamp = (start_time + timedelta(seconds=i * 30)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            
            # Inject suspicious behaviors randomly every 15 lines
            if i % 15 == 0:
                ip = "185.220.101.5"  # Attacker IP
                path = random.choice(sqli_payloads)
                status = 500
            elif i % 22 == 0:
                ip = "45.33.22.11"   # Attacker IP
                path = random.choice(xss_payloads)
                status = 404
            else:
                path = random.choice(paths)

            # Standard Common Log Format (CLF)
            log_line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size}\n'
            f.write(log_line)
    print("[+] Log file generation complete.\n")

# ==========================================
# 2. PARSE LOGS USING REGEX & PANDAS
# ==========================================
def analyze_logs(filename="server_access.log"):
    # Unified regex matching: IP, Timestamp, Method, Path, Status Code, Response Size
    log_regex = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<path>.*?) HTTP\/1\.[01]" (?P<status>\d{3}) (?P<size>\d+)'
    
    # Attack identification regex
    sqli_regex = r"(\bOR\b|=|\bUNION\b|--|')" 
    xss_regex = r"(<script>|%3Cscript%3E|alert)"

    parsed_data = []

    print(f"[*] Parsing logs from '{filename}' via Regular Expressions...")
    with open(filename, "r") as f:
        for line in f:
            match = re.match(log_regex, line)
            if match:
                data = match.groupdict()
                
                # Tag security threats based on pattern match
                if re.search(sqli_regex, data['path'], re.IGNORECASE):
                    data['security_tag'] = 'SQL Injection Attempt'
                elif re.search(xss_regex, data['path'], re.IGNORECASE):
                    data['security_tag'] = 'Cross-Site Scripting (XSS)'
                else:
                    data['security_tag'] = 'Normal Traffic'
                    
                parsed_data = parsed_data + [data]

    # Convert list of dicts to Pandas DataFrame
    df = pd.DataFrame(parsed_data)
    df['status'] = df['status'].astype(int)
    df['size'] = df['size'].astype(int)
    
    return df
generate_mock_logs()


# ==========================================
# 3. RUN INTERACTIVE ANALYSIS
# ==========================================
if __name__ == "__main__":
    log_file = "security_access.log"
    
    # 1. Execute Pipeline
    generate_mock_logs(log_file, num_lines=250)
    df = analyze_logs(log_file)
    
    # 2. Generate Security Metrics
    print("\n=== SYSTEM METRICS & SECURITY INSIGHTS ===")
    
    print("\n[+] Total Requests by Security Tag:")
    print(df['security_tag'].value_counts())
    
    print("\n[+] Suspicious IPs Detected:")
    suspicious_df = df[df['security_tag'] != 'Normal Traffic']
    print(suspicious_df.groupby(['ip', 'security_tag']).size().reset_index(name='attack_count'))
    
    print("\n[+] Most Visited URL Paths (Top 5):")
    print(df['path'].value_counts().head(5))
    
    # Save parsed data to CSV for portfolio showcase
    df.to_csv("parsed_security_logs.csv", index=False)
    print("\n[+] Structured analytics saved cleanly to 'parsed_security_logs.csv'")
    