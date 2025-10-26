import time
import datetime
import os
from typing import List, Dict, Any

class SubdomainLogger:
    def __init__(self):
        self.setup_logger()
    
    def setup_logger(self):
        """Setup real-time logging"""
        self.start_time = datetime.datetime.now()
    
    def _log_real_time(self, message: str, delay: float = 0.5):
        """Log message with real-time timestamp and delay"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        pid = os.getpid()
        thread_id = 8595  # Static thread ID kama LSPosed
        
        print(f"[{timestamp} {pid}:{thread_id} I/EVILWAF-SUMMARY] {message}")
        time.sleep(delay)
    
    def log_summary_start(self, domain: str):
        """Log scan initiation"""
        self._log_real_time(f"SUBDOMAIN_SCAN_STARTED domain={domain}", 0.3)
    
    def log_statistics(self, stats: Dict[str, Any]):
        """Log statistical summary"""
        message = (f"STATS total_tested={stats['total_tested']} "
                  f"dns_found={stats['dns_found']} "
                  f"bypass_success={stats['bypass_success']} "
                  f"success_rate={stats['success_rate']:.1f}%")
        self._log_real_time(message, 0.4)
    
    def log_dns_records(self, valid_subdomains: List[str], working_subs: List[str]):
        """Log all DNS records found"""
        for i, subdomain in enumerate(valid_subdomains, 1):
            status = "BYPASS_SUCCESS" if subdomain in working_subs else "BYPASS_FAILED"
            self._log_real_time(f"DNS_RECORD #{i:03d} subdomain={subdomain} status={status}", 0.1)
    
    def log_successful_bypasses(self, working_subs: List[str]):
        """Log only successful bypasses"""
        for i, subdomain in enumerate(working_subs, 1):
            self._log_real_time(f"BYPASS_SUCCESS #{i:02d} subdomain={subdomain}", 0.2)
    
    def log_failed_dns(self, failed_subs: List[str]):
        """Log DNS failures"""
        for i, subdomain in enumerate(failed_subs, 1):
            self._log_real_time(f"DNS_FAILED #{i:03d} subdomain={subdomain}", 0.1)
    
    def log_bypass_failures(self, bypass_failed_subs: List[str]):
        """Log bypass failures"""
        for i, subdomain in enumerate(bypass_failed_subs, 1):
            self._log_real_time(f"BYPASS_FAILED #{i:03d} subdomain={subdomain}", 0.1)
    
    def log_scan_completion(self, final_success_rate: float, bypass_success: int, total_tested: int):
        """Log scan completion"""
        message = f"SCAN_COMPLETED success_rate={final_success_rate:.1f}% bypassed={bypass_success}/{total_tested}"
        self._log_real_time(message, 0.5)
