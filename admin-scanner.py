#!/usr/bin/env python3
"""
Admin Panel Discovery Tool - Professional Edition
Advanced reconnaissance tool for discovering administrative interfaces
Author: Security Research Team
Version: 2.0
"""

import argparse
import asyncio
import aiohttp
import json
import csv
import random
import time
import sys
import os
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import ssl
import certifi

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    @staticmethod
    def disable():
        """Disable colors for non-terminal output"""
        Colors.HEADER = Colors.BLUE = Colors.CYAN = ''
        Colors.GREEN = Colors.YELLOW = Colors.RED = ''
        Colors.BOLD = Colors.UNDERLINE = Colors.RESET = ''

@dataclass
class ScanResult:
    url: str
    status_code: int
    response_time: float
    redirect_url: Optional[str]
    content_length: int
    server: Optional[str]
    title: Optional[str]
    admin_indicators: List[str]

class AdminPanelFinder:
    """Professional Admin Panel Discovery Tool"""
    
    # Enhanced list of admin paths
    ADMIN_PATHS = [
        # Common admin paths
        "admin", "administrator", "wp-admin", "wp-login.php", "login", "panel", 
        "controlpanel", "cp", "dashboard", "manager", "admincp", "adminpanel",
        "sysadmin", "system", "webadmin", "backend", "secure", "private",
        
        # Framework specific
        "admin/login", "admin_area", "admin-console", "admin-login", "admin1",
        "admin2", "administrator/login", "siteadmin", "memberadmin", "useradmin",
        "admin/account", "admin/home", "admin/controlpanel", "admin/cp",
        
        # CMS specific
        "wp-admin/", "wp-login.php", "administrator/", "admin.php", "login.php",
        "admin/admin.php", "admin_area/admin.php", "admin_area/login.php",
        "admin_area/index.php", "bb-admin/", "admin/login.aspx", "admin.aspx",
        
        # Application specific
        "phpmyadmin", "pma", "mysql", "sql", "database", "db", "phpMyAdmin",
        "adminer", "adminer.php", "manager/html", "tomcat/manager", "jmx-console",
        "web-console", "admin-console", "management", "monitoring",
        
        # Directory variations
        "admin/", "admin/index.php", "admin/index.html", "admin/login/",
        "administrator/", "administrator/index.php", "cpanel", "cPanel",
        "plesk", "directadmin", "webmin", "usermin",
        
        # Security appliances
        "auth", "authentication", "signin", "sign-in", "access", "console",
        "terminal", "shell", "cmd", "exec", "api", "api/v1", "rest",
        
        # Custom paths
        "backoffice", "bo", "office", "corporate", "intranet", "internal",
        "staff", "employee", "member", "user", "account", "profile",
        "settings", "config", "configuration", "setup", "install"
    ]
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    ]
    
    ADMIN_INDICATORS = [
        "login", "password", "username", "admin", "administrator", "dashboard",
        "control panel", "management", "authentication", "signin", "log in",
        "user name", "pass word", "submit", "enter", "access denied", "unauthorized"
    ]

    def __init__(self, target: str, **kwargs):
        self.target = self._normalize_target(target)
        self.threads = kwargs.get('threads', 20)
        self.timeout = kwargs.get('timeout', 10)
        self.delay = kwargs.get('delay', 0)
        self.output = kwargs.get('output')
        self.verbose = kwargs.get('verbose', False)
        self.follow_redirects = kwargs.get('follow_redirects', True)
        self.verify_ssl = kwargs.get('verify_ssl', False)
        
        self.results: List[ScanResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.start_time = 0
        self.total_requests = 0
        self.successful_requests = 0
        
        # Disable colors if output is redirected
        if not sys.stdout.isatty():
            Colors.disable()

    def _normalize_target(self, target: str) -> str:
        """Normalize and validate target URL"""
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        
        # Remove trailing slash
        target = target.rstrip('/')
        
        # Validate URL
        try:
            parsed = urlparse(target)
            if not parsed.netloc:
                raise ValueError("Invalid URL format")
        except Exception:
            raise ValueError(f"Invalid target URL: {target}")
        
        return target

    def _print_banner(self):
        """Display professional banner"""
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║              {Colors.BOLD}ADMIN PANEL DISCOVERY TOOL{Colors.RESET}{Colors.CYAN}                 ║
║                     {Colors.YELLOW}Professional Edition{Colors.RESET}{Colors.CYAN}                    ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.BLUE}Target:{Colors.RESET}     {Colors.BOLD}{self.target}{Colors.RESET}
{Colors.BLUE}Threads:{Colors.RESET}    {Colors.BOLD}{self.threads}{Colors.RESET}
{Colors.BLUE}Timeout:{Colors.RESET}    {Colors.BOLD}{self.timeout}s{Colors.RESET}
{Colors.BLUE}Paths:{Colors.RESET}      {Colors.BOLD}{len(self.ADMIN_PATHS)}{Colors.RESET}
{Colors.BLUE}SSL Verify:{Colors.RESET} {Colors.BOLD}{'Yes' if self.verify_ssl else 'No'}{Colors.RESET}

{Colors.YELLOW}{'='*64}{Colors.RESET}
"""
        print(banner)

    async def _check_admin_path(self, path: str) -> Optional[ScanResult]:
        """Check a single admin path with enhanced detection"""
        url = urljoin(self.target, path)
        start_time = time.time()
        
        try:
            headers = {
                'User-Agent': random.choice(self.USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            async with self.session.get(
                url, 
                headers=headers, 
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=self.follow_redirects,
                ssl=self.verify_ssl
            ) as response:
                
                self.total_requests += 1
                response_time = time.time() - start_time
                
                # Check if response indicates potential admin panel
                if self._is_potential_admin_panel(response):
                    self.successful_requests += 1
                    
                    content = await response.text()
                    admin_indicators = self._extract_admin_indicators(content)
                    title = self._extract_title(content)
                    
                    result = ScanResult(
                        url=url,
                        status_code=response.status,
                        response_time=response_time,
                        redirect_url=str(response.url) if str(response.url) != url else None,
                        content_length=len(content),
                        server=response.headers.get('Server'),
                        title=title,
                        admin_indicators=admin_indicators
                    )
                    
                    if self.verbose:
                        self._print_found_panel(result)
                    
                    return result
                    
        except asyncio.TimeoutError:
            if self.verbose:
                print(f"{Colors.YELLOW}[TIMEOUT]{Colors.RESET} {url}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} {url} - {str(e)}")
        
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        
        return None

    def _is_potential_admin_panel(self, response) -> bool:
        """Determine if response indicates potential admin panel"""
        status = response.status
        
        # Check status codes that might indicate admin panels
        if status in [200, 401, 403, 302, 301]:
            return True
        
        # Check for specific headers
        auth_header = response.headers.get('WWW-Authenticate', '')
        if 'basic' in auth_header.lower() or 'digest' in auth_header.lower():
            return True
            
        return False

    def _extract_admin_indicators(self, content: str) -> List[str]:
        """Extract admin-related keywords from content"""
        content_lower = content.lower()
        found_indicators = []
        
        for indicator in self.ADMIN_INDICATORS:
            if indicator in content_lower:
                found_indicators.append(indicator)
        
        return found_indicators

    def _extract_title(self, content: str) -> Optional[str]:
        """Extract page title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return None

    def _print_found_panel(self, result: ScanResult):
        """Print discovered admin panel with formatting"""
        status_color = Colors.GREEN if result.status_code == 200 else Colors.YELLOW
        print(f"{Colors.GREEN}[FOUND]{Colors.RESET} {result.url}")
        print(f"  └─ Status: {status_color}{result.status_code}{Colors.RESET} | "
              f"Time: {result.response_time:.2f}s | "
              f"Size: {result.content_length} bytes")
        
        if result.title:
            print(f"  └─ Title: {Colors.CYAN}{result.title}{Colors.RESET}")
        
        if result.redirect_url:
            print(f"  └─ Redirect: {Colors.BLUE}{result.redirect_url}{Colors.RESET}")

    async def scan(self):
        """Execute the admin panel discovery scan"""
        self._print_banner()
        self.start_time = time.time()
        
        # Create SSL context
        ssl_context = ssl.create_default_context(cafile=certifi.where()) if self.verify_ssl else False
        
        # Configure session
        connector = aiohttp.TCPConnector(
            limit=self.threads,
            ssl=ssl_context,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector, 
            timeout=timeout,
            headers={'User-Agent': random.choice(self.USER_AGENTS)}
        ) as session:
            self.session = session
            
            print(f"{Colors.BLUE}[INFO]{Colors.RESET} Starting scan with {self.threads} concurrent threads...")
            print(f"{Colors.BLUE}[INFO]{Colors.RESET} Scanning {len(self.ADMIN_PATHS)} potential admin paths...\n")
            
            # Create semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(self.threads)
            
            async def bounded_check(path):
                async with semaphore:
                    return await self._check_admin_path(path)
            
            # Execute scan
            tasks = [bounded_check(path) for path in self.ADMIN_PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter valid results
            self.results = [r for r in results if isinstance(r, ScanResult)]
        
        self._print_summary()
        
        if self.output:
            self._save_results()

    def _print_summary(self):
        """Print comprehensive scan summary"""
        elapsed_time = time.time() - self.start_time
        
        print(f"\n{Colors.CYAN}{'='*64}{Colors.RESET}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*64}{Colors.RESET}")
        
        print(f"{Colors.BLUE}Target URL:{Colors.RESET}        {self.target}")
        print(f"{Colors.BLUE}Total Requests:{Colors.RESET}    {self.total_requests}")
        print(f"{Colors.BLUE}Admin Panels Found:{Colors.RESET} {Colors.GREEN}{len(self.results)}{Colors.RESET}")
        print(f"{Colors.BLUE}Success Rate:{Colors.RESET}      {(len(self.results)/max(self.total_requests, 1)*100):.1f}%")
        print(f"{Colors.BLUE}Elapsed Time:{Colors.RESET}      {elapsed_time:.2f} seconds")
        print(f"{Colors.BLUE}Request Rate:{Colors.RESET}      {(self.total_requests/elapsed_time):.1f} req/sec")
        
        if self.results:
            print(f"\n{Colors.GREEN}[DISCOVERED ADMIN PANELS]{Colors.RESET}")
            print(f"{Colors.GREEN}{'─'*50}{Colors.RESET}")
            
            for i, result in enumerate(self.results, 1):
                status_color = Colors.GREEN if result.status_code == 200 else Colors.YELLOW
                print(f"{Colors.BOLD}{i:2d}.{Colors.RESET} {result.url}")
                print(f"     Status: {status_color}{result.status_code}{Colors.RESET} | "
                      f"Time: {result.response_time:.2f}s | "
                      f"Size: {result.content_length:,} bytes")
                
                if result.title:
                    print(f"     Title: {Colors.CYAN}{result.title[:60]}{'...' if len(result.title) > 60 else ''}{Colors.RESET}")
                
                if result.server:
                    print(f"     Server: {Colors.BLUE}{result.server}{Colors.RESET}")
                
                if result.admin_indicators:
                    indicators = ', '.join(result.admin_indicators[:5])
                    print(f"     Indicators: {Colors.YELLOW}{indicators}{Colors.RESET}")
                
                if result.redirect_url:
                    print(f"     Redirect: {Colors.BLUE}{result.redirect_url}{Colors.RESET}")
                
                print()
        else:
            print(f"\n{Colors.YELLOW}[NO ADMIN PANELS FOUND]{Colors.RESET}")
            print("Consider trying:")
            print("• Different wordlists or custom paths")
            print("• Subdomain enumeration")
            print("• Directory bruteforcing")
            print("• Port scanning for alternative services")

    def _save_results(self):
        """Save results to specified output format"""
        if not self.results:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} No results to save")
            return
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if self.output.endswith('.json'):
                self._save_json()
            elif self.output.endswith('.csv'):
                self._save_csv()
            elif self.output.endswith('.html'):
                self._save_html()
            else:
                self._save_txt()
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Results saved to {Colors.BOLD}{self.output}{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to save results: {str(e)}")

    def _save_json(self):
        """Save results as JSON"""
        data = {
            'scan_info': {
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'total_paths': len(self.ADMIN_PATHS),
                'found_panels': len(self.results),
                'scan_duration': time.time() - self.start_time
            },
            'results': [
                {
                    'url': r.url,
                    'status_code': r.status_code,
                    'response_time': r.response_time,
                    'redirect_url': r.redirect_url,
                    'content_length': r.content_length,
                    'server': r.server,
                    'title': r.title,
                    'admin_indicators': r.admin_indicators
                }
                for r in self.results
            ]
        }
        
        with open(self.output, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _save_csv(self):
        """Save results as CSV"""
        with open(self.output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'URL', 'Status Code', 'Response Time (s)', 'Redirect URL',
                'Content Length', 'Server', 'Title', 'Admin Indicators'
            ])
            
            for result in self.results:
                writer.writerow([
                    result.url,
                    result.status_code,
                    f"{result.response_time:.2f}",
                    result.redirect_url or '',
                    result.content_length,
                    result.server or '',
                    result.title or '',
                    ', '.join(result.admin_indicators)
                ])

    def _save_txt(self):
        """Save results as plain text"""
        with open(self.output, 'w', encoding='utf-8') as f:
            f.write(f"Admin Panel Discovery Report\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Panels Found: {len(self.results)}\n")
            f.write("="*60 + "\n\n")
            
            for i, result in enumerate(self.results, 1):
                f.write(f"{i}. {result.url}\n")
                f.write(f"   Status: {result.status_code}\n")
                f.write(f"   Response Time: {result.response_time:.2f}s\n")
                if result.title:
                    f.write(f"   Title: {result.title}\n")
                if result.server:
                    f.write(f"   Server: {result.server}\n")
                if result.redirect_url:
                    f.write(f"   Redirect: {result.redirect_url}\n")
                f.write("\n")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Professional Admin Panel Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s https://target.com -t 50 -v
  %(prog)s target.com -o results.json --timeout 15
  %(prog)s https://site.com -o report.html --no-ssl-verify
        """
    )
    
    parser.add_argument(
        'target',
        help='Target URL (e.g., example.com or https://example.com)'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=20,
        help='Number of concurrent threads (default: 20)'
    )
    
    parser.add_argument(
        '-T', '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=0,
        help='Delay between requests in seconds (default: 0)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file (supports .txt, .json, .csv, .html)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--no-redirects',
        action='store_true',
        help='Do not follow HTTP redirects'
    )
    
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        help='Verify SSL certificates (default: disabled)'
    )
    
    args = parser.parse_args()
    
    try:
        finder = AdminPanelFinder(
            target=args.target,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            output=args.output,
            verbose=args.verbose,
            follow_redirects=not args.no_redirects,
            verify_ssl=args.verify_ssl
        )
        
        asyncio.run(finder.scan())
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INTERRUPTED]{Colors.RESET} Scan cancelled by user")
        sys.exit(1)
    except ValueError as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[CRITICAL ERROR]{Colors.RESET} {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
