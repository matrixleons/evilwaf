import time
import datetime
import os
import re
from typing import List, Dict, Any

class SmugglingLogger:
    def __init__(self):
        self.setup_logger()
    
    def setup_logger(self):
        """Setup real-time logging"""
        self.start_time = datetime.datetime.now()
    
    def _log_real_time(self, message: str, delay: float = 0.5):
        """Log message with real-time timestamp and delay"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        pid = os.getpid()
        thread_id = 8595
        
        print(f"[{timestamp} {pid}:{thread_id} I/EVILWAF-SMUGGLING] {message}")
        time.sleep(delay)
    
    def log_scan_start(self, domain: str):
        """Log smuggling scan initiation"""
        self._log_real_time(f"SMUGGLING_SCAN_STARTED domain={domain}", 0.3)
    
    def log_statistics(self, total_payloads: int, success_payloads: int, success_rate: float):
        """Log statistical summary"""
        message = (f"STATS total_payloads={total_payloads} "
                  f"success_payloads={success_payloads} "
                  f"success_rate={success_rate:.1f}%")
        self._log_real_time(message, 0.4)
    
    def log_successful_payloads(self, working_smuggles: List[str]):
        """Log all successful smuggling payloads"""
        for i, payload in enumerate(working_smuggles, 1):
            # Determine attack type
            if "CL.TE" in payload or ("Content-Length" in payload and "Transfer-Encoding: chunked" in payload):
                attack_type = "CL.TE"
            elif "TE.CL" in payload:
                attack_type = "TE.CL"
            elif "Transfer-Encoding :" in payload or "Transfer-Encoding:\t" in payload:
                attack_type = "OBFUSCATION"
            elif "X-Forwarded-For" in payload or "X-Real-IP" in payload:
                attack_type = "HEADER_INJECTION"
            elif "chunk-extension" in payload:
                attack_type = "CHUNK_EXTENSION"
            else:
                attack_type = "STANDARD"
            
            # Extract target path
            target_match = re.search(r'GET\s+([^\s]+)\s+HTTP', payload)
            target_path = target_match.group(1) if target_match else "Unknown"
            
            self._log_real_time(f"SUCCESS_PAYLOAD #{i:02d} type={attack_type} target={target_path}", 0.2)
    
    def log_attack_categories(self, category_counts: Dict[str, int], success_payloads: int):
        """Log attack categories breakdown"""
        for category, count in category_counts.items():
            if count > 0:
                percent = (count / success_payloads) * 100 if success_payloads > 0 else 0
                self._log_real_time(f"CATEGORY {category.replace(' ', '_').upper()} count={count} percentage={percent:.1f}%", 0.2)
    
    def log_technique_effectiveness(self, technique_stats: Dict[str, int]):
        """Log technique effectiveness analysis"""
        for tech, count in technique_stats.items():
            self._log_real_time(f"TECHNIQUE {tech.replace(' ', '_').upper()} successful={count}", 0.2)
    
    def log_vulnerable_paths(self, target_paths: List[str]):
        """Log vulnerable target paths"""
        unique_targets = list(set(target_paths))
        for i, target in enumerate(unique_targets[:10], 1):
            self._log_real_time(f"VULNERABLE_PATH #{i:02d} path={target}", 0.1)
        
        if len(unique_targets) > 10:
            self._log_real_time(f"VULNERABLE_PATHS additional_paths={len(unique_targets) - 10}", 0.1)
    
    def log_scan_completion(self, success_rate: float, success_payloads: int, total_payloads: int):
        """Log scan completion"""
        message = f"SCAN_COMPLETED success_rate={success_rate:.1f}% successful={success_payloads}/{total_payloads}"
        self._log_real_time(message, 0.5)
