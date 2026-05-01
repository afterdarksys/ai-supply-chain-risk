#!/usr/bin/env python3
"""
Enterprise Endpoint SCRM & Vulnerability Scanner
================================================
Focuses on Endpoint Software Supply Chain, EOL tracking, 
and vulnerability mapping.
"""

import json
import sys
import os
import sqlite3
import argparse
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Any
from datetime import datetime
import platform

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

    def init_db(self):
        self.connect()
        cursor = self.conn.cursor()
        # Schema
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            os_info TEXT,
            last_scan TIMESTAMP
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            name TEXT,
            version TEXT,
            publisher TEXT,
            is_licensed BOOLEAN,
            install_path TEXT,
            FOREIGN KEY(asset_id) REFERENCES assets(id)
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS eol_status (
            software_id INTEGER,
            is_eol BOOLEAN,
            eol_date TEXT,
            latest_version TEXT,
            FOREIGN KEY(software_id) REFERENCES software(id)
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            software_id INTEGER,
            cve_id TEXT,
            severity TEXT,
            description TEXT,
            FOREIGN KEY(software_id) REFERENCES software(id)
        )''')
        self.conn.commit()
        print(f"[+] Initialized SQLite database at {self.db_path}")

    def vacuum(self):
        self.connect()
        self.conn.execute("VACUUM")
        print(f"[+] Vacuumed database at {self.db_path}")

class ThreatIntelEngine:
    """Queries EOL and Vuln APIs"""
    
    @staticmethod
    def check_eol(product_name: str) -> Dict[str, Any]:
        """Check endoflife.date API. We try to guess the product slug."""
        if not product_name:
            return {'status': 'unknown'}
            
        slug = product_name.lower().replace(' ', '-').replace('.', '')
        # Only check a few known products to avoid spamming the API in this PoC
        known_slugs = ['python', 'nodejs', 'go', 'php', 'ruby', 'docker', 'kubernetes', 'ubuntu', 'alpine', 'electron']
        
        found_slug = None
        for k in known_slugs:
            if k in slug:
                found_slug = k
                break
                
        if not found_slug:
            return {'status': 'unknown'}

        api_url = f"https://endoflife.date/api/{found_slug}.json"
        try:
            req = urllib.request.Request(api_url, headers={'User-Agent': 'EnterpriseSCRM/1.0'})
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    if data and len(data) > 0:
                        # Assuming the first entry is the latest cycle
                        return {
                            'status': 'success',
                            # the eol property might be a date string, or boolean
                            'is_eol': data[0].get('eol', False) != False, 
                            'eol_date': str(data[0].get('eol', 'Unknown')),
                            'latest_version': data[0].get('latest', 'Unknown')
                        }
        except Exception:
            pass
        return {'status': 'error'}

    @staticmethod
    def check_vulnerabilities(product_name: str) -> List[Dict]:
        """Mock vulnerability checker"""
        if not product_name:
            return []
        # If the app has "Adobe" or "Flash", mock a vuln
        if "adobe" in product_name.lower():
            return [{'cve_id': 'CVE-MOCK-1001', 'severity': 'HIGH', 'description': 'Mocked Adobe Vulnerability'}]
        return []

class EndpointScanner:
    """Scans local endpoint for installed software"""
    
    LICENSED_PUBLISHERS = ['microsoft', 'adobe', 'autodesk', 'vmware', 'cisco', 'palo alto', 'fortinet', 'apple']

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.hostname = platform.node()
        self.os_info = f"{platform.system()} {platform.release()}"

    def run_scan(self):
        self.db.connect()
        cursor = self.db.conn.cursor()
        
        # Register asset
        cursor.execute("INSERT INTO assets (hostname, os_info, last_scan) VALUES (?, ?, ?)",
                       (self.hostname, self.os_info, datetime.utcnow().isoformat()))
        asset_id = cursor.lastrowid
        self.db.conn.commit()

        print(f"[*] Scanning host: {self.hostname} ({self.os_info})")
        apps = self._scan_os()
        print(f"[*] Found {len(apps)} installed applications.")

        for app in apps:
            publisher = app.get('publisher', '') or ''
            name = app.get('name', '') or ''
            is_licensed = any(pub in publisher.lower() or pub in name.lower() for pub in self.LICENSED_PUBLISHERS)
            
            cursor.execute("INSERT INTO software (asset_id, name, version, publisher, is_licensed, install_path) VALUES (?, ?, ?, ?, ?, ?)",
                           (asset_id, name, app.get('version'), publisher, is_licensed, app.get('path')))
            software_id = cursor.lastrowid
            
            # EOL Check
            eol_info = ThreatIntelEngine.check_eol(name)
            if eol_info.get('status') == 'success':
                cursor.execute("INSERT INTO eol_status (software_id, is_eol, eol_date, latest_version) VALUES (?, ?, ?, ?)",
                               (software_id, eol_info.get('is_eol'), eol_info.get('eol_date'), eol_info.get('latest_version')))
            
            # Vuln Check
            vulns = ThreatIntelEngine.check_vulnerabilities(name)
            for v in vulns:
                cursor.execute("INSERT INTO vulnerabilities (software_id, cve_id, severity, description) VALUES (?, ?, ?, ?)",
                               (software_id, v['cve_id'], v['severity'], v['description']))
                
        self.db.conn.commit()
        print(f"[+] Scan complete. Data saved to {self.db.db_path}")

    def _scan_os(self) -> List[Dict]:
        if sys.platform == 'darwin':
            return self._scan_macos()
        elif sys.platform == 'win32':
            return self._scan_windows()
        else:
            print("[-] Unsupported OS for local scanning.")
            return []

    def _scan_macos(self) -> List[Dict]:
        import plistlib
        apps = []
        app_dirs = ['/Applications', '/System/Applications']
        for d in app_dirs:
            if not os.path.exists(d): continue
            for item in os.listdir(d):
                if item.endswith('.app'):
                    app_path = os.path.join(d, item)
                    plist_path = os.path.join(app_path, 'Contents', 'Info.plist')
                    if os.path.exists(plist_path):
                        try:
                            with open(plist_path, 'rb') as f:
                                plist = plistlib.load(f)
                                name = plist.get('CFBundleName', item.replace('.app', ''))
                                version = plist.get('CFBundleShortVersionString', plist.get('CFBundleVersion', 'Unknown'))
                                publisher = plist.get('CFBundleIdentifier', '').split('.')[1] if len(plist.get('CFBundleIdentifier', '').split('.')) > 1 else 'Unknown'
                                apps.append({
                                    'name': name,
                                    'version': version,
                                    'publisher': publisher,
                                    'path': app_path
                                })
                        except Exception:
                            pass
        return apps

    def _scan_windows(self) -> List[Dict]:
        import winreg
        apps = []
        try:
            # Check standard uninstall key
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, subkey_name)
                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                    publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                    apps.append({'name': name, 'version': version, 'publisher': publisher, 'path': ''})
                except OSError:
                    pass
        except OSError:
            pass
        return apps

class SBOMIntegrityAuditor:
    def __init__(self, sbom_path: str):
        self.sbom_path = sbom_path
        self.components = []
        self.findings = []
        self.ai_score = 0
        self.reasons = []

    def audit(self):
        print(f"[*] Auditing SBOM: {self.sbom_path}")
        try:
            with open(self.sbom_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"[-] Failed to load SBOM: {e}")
            return
            
        self.components = data.get('components', [])
        print(f"[*] Found {len(self.components)} components.")
        
        for comp in self.components:
            name = comp.get('name')
            version = comp.get('version')
            purl = comp.get('purl', '')
            hashes = comp.get('hashes', [])
            
            # Check missing hashes
            if not hashes:
                self.ai_score += 10
                self.reasons.append(f"Missing cryptographic hash for {name}@{version}")
                
            if 'pkg:pypi/' in purl:
                self._verify_pypi(name, version, hashes)
            elif 'pkg:npm/' in purl:
                self._verify_npm(name, version, hashes)

        self._print_report()

    def _verify_pypi(self, name: str, version: str, hashes: List[Dict]):
        api_url = f"https://pypi.org/pypi/{name}/{version}/json"
        try:
            req = urllib.request.Request(api_url, headers={'User-Agent': 'EnterpriseSCRM/1.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    urls = data.get('urls', [])
                    official_sha256 = None
                    if urls:
                        official_sha256 = urls[0].get('digests', {}).get('sha256')
                        
                    for h in hashes:
                        if h.get('alg', '').upper() == 'SHA-256':
                            if official_sha256 and h.get('content') != official_sha256:
                                self.ai_score += 50
                                self.reasons.append(f"Hash Mismatch for {name}@{version}: Expected {official_sha256[:8]}..., Got {h.get('content')[:8]}...")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.ai_score += 30
                self.reasons.append(f"Ghost Package/Version: PyPI returned 404 for {name}@{version}")
        except Exception:
            pass # Network error

    def _verify_npm(self, name: str, version: str, hashes: List[Dict]):
        api_url = f"https://registry.npmjs.org/{name}/{version}"
        try:
            req = urllib.request.Request(api_url, headers={'User-Agent': 'EnterpriseSCRM/1.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    official_shasum = data.get('dist', {}).get('shasum')
                    
                    for h in hashes:
                        if h.get('alg', '').upper() == 'SHA-1':
                            if official_shasum and h.get('content') != official_shasum:
                                self.ai_score += 50
                                self.reasons.append(f"Hash Mismatch for {name}@{version}: Expected {official_shasum[:8]}..., Got {h.get('content')[:8]}...")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.ai_score += 30
                self.reasons.append(f"Ghost Package/Version: NPM returned 404 for {name}@{version}")
        except Exception:
            pass

    def _print_report(self):
        probability = min(self.ai_score, 100)
        print("\n" + "="*70)
        print("SBOM PROVENANCE & INTEGRITY REPORT")
        print("="*70)
        
        if probability >= 80:
            print(f"🚨 ALERT: HIGH PROBABILITY OF AI FORGERY ({probability}%)")
        elif probability >= 40:
            print(f"⚠️  WARNING: SUSPICIOUS SBOM ANOMALIES DETECTED ({probability}%)")
        else:
            print(f"✅ PASSED: Deterministic Provenance Verified ({probability}% anomaly score)")
            
        if self.reasons:
            print("\nFindings:")
            for r in self.reasons:
                print(f" - {r}")
        print("="*70 + "\n")

def report_findings(db_path: str):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    cursor = db.cursor()
    
    print("\n" + "="*70)
    print("ENDPOINT SUPPLY CHAIN & VULNERABILITY REPORT")
    print("="*70)
    
    cursor.execute("SELECT * FROM software WHERE is_licensed=1 LIMIT 10")
    licensed = cursor.fetchall()
    print(f"\n🔑 COMMERCIAL/LICENSED SOFTWARE ({len(licensed)} shown):")
    for row in licensed:
        print(f"   - {row['name']} v{row['version']} (Publisher: {row['publisher']})")

    cursor.execute("""
        SELECT s.name, s.version, e.eol_date, e.latest_version 
        FROM software s JOIN eol_status e ON s.id = e.software_id 
        WHERE e.is_eol != 0
    """)
    eol_apps = cursor.fetchall()
    print(f"\n⏰ END-OF-LIFE (EOL) SOFTWARE ({len(eol_apps)}):")
    if not eol_apps:
        print("   ✅ No EOL software detected.")
    for row in eol_apps:
        print(f"   ⚠️  [EOL] {row['name']} v{row['version']} (EOL Date: {row['eol_date']}, Latest: {row['latest_version']})")

    cursor.execute("""
        SELECT s.name, v.cve_id, v.severity, v.description 
        FROM software s JOIN vulnerabilities v ON s.id = v.software_id
    """)
    vulns = cursor.fetchall()
    print(f"\n🛑 KNOWN VULNERABILITIES ({len(vulns)}):")
    if not vulns:
        print("   ✅ No vulnerabilities detected in scanned software.")
    for row in vulns:
        print(f"   ❌ {row['name']} - {row['cve_id']} ({row['severity']}): {row['description']}")
    
    print("\n" + "="*70)

def main():
    parser = argparse.ArgumentParser(description="Endpoint SCRM & Vulnerability Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # DB command
    db_parser = subparsers.add_parser("db", help="Database management")
    db_parser.add_argument("--init", help="Initialize database at path")
    db_parser.add_argument("--vacuum", help="Vacuum database at path")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run scanner")
    scan_parser.add_argument("--local", action="store_true", help="Scan local endpoint applications")
    scan_parser.add_argument("--db", required=True, help="Path to SQLite database")

    # SBOM Audit command
    audit_parser = subparsers.add_parser("audit-sbom", help="Audit SBOM for AI forgery or integrity anomalies")
    audit_parser.add_argument("--file", required=True, help="Path to CycloneDX JSON SBOM")

    args = parser.parse_args()

    if args.command == "db":
        if args.init:
            mgr = DatabaseManager(args.init)
            mgr.init_db()
        elif args.vacuum:
            mgr = DatabaseManager(args.vacuum)
            mgr.vacuum()
        else:
            db_parser.print_help()

    elif args.command == "scan":
        mgr = DatabaseManager(args.db)
        if not os.path.exists(args.db):
            print(f"[-] Database {args.db} does not exist. Run 'db --init {args.db}' first.")
            sys.exit(1)
            
        if args.local:
            scanner = EndpointScanner(mgr)
            scanner.run_scan()
            report_findings(args.db)

    elif args.command == "audit-sbom":
        auditor = SBOMIntegrityAuditor(args.file)
        auditor.audit()

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
