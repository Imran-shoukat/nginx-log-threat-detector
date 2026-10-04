# Nginx Log Threat Detector

A small tool I built to parse nginx-style access logs and flag basic SQL injection and XSS attempts using regex, then analyze the results with Pandas.

I wanted to understand how log parsing and basic intrusion detection actually work under the hood, so this starts from raw text logs, no external libraries doing the heavy lifting, just regex and pandas.

## What it does

1. Generates a mock nginx access log (since I don't have a live server to pull real ones from), with SQLi and XSS payloads mixed in at random intervals to simulate an attack.
2. Parses each log line with a regex pattern to extract IP, timestamp, method, path, status code, and response size.
3. Checks each request's path against known SQLi and XSS signatures and tags it accordingly.
4. Loads everything into a Pandas DataFrame and generates summary stats: traffic breakdown by tag, which IPs are suspicious, most-requested paths.
5. Exports the structured, tagged data to CSV.

## Example output

| ip | status | path | security_tag |
|---|---|---|---|
| 185.220.101.5 | 500 | /products?id=1%20OR%201=1 | SQL Injection Attempt |
| 10.0.0.12 | 200 | /dashboard | Normal Traffic |

See `/examples` for full sample output.

## How to run

```bash
pip install pandas
python log_analyzer.py
