import time
import datetime
import os
from typing import List, Dict, Any

class CachePoisoningLogger:
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
        
        print(f"[{timestamp} {pid}:{thread_id} I/EVILWAF-CACHE] {message}")
        time.sleep(delay)
    
    def log_scan_start(self, domain: str):
        """Log cache poisoning scan initiation"""
        self._log_real_time(f"CACHE_POISONING_SCAN_STARTED domain={domain}", 0.3)
    
    def log_statistics(self, total_payloads: int, success_payloads: int, success_rate: float):
        """Log statistical summary"""
        message = (f"STATS total_payloads={total_payloads} "
                  f"success_payloads={success_payloads} "
                  f"success_rate={success_rate:.1f}%")
        self._log_real_time(message, 0.4)
    
    def log_successful_techniques(self, results: List[Dict], deception_payloads: List[Dict]):
        """Log all successful cache deception techniques"""
        for i, result in enumerate(results, 1):
            technique = result['technique']
            url = result['url']
            status = result['status']
            
            # Find payload used
            payload = self.find_payload_by_description(deception_payloads, technique)
            payload_suffix = payload['url_suffix'] if payload else "Unknown"
            
            # Determine deception type
            deception_type = self.get_deception_type(technique)
            
            self._log_real_time(f"SUCCESS_TECHNIQUE #{i:02d} type={deception_type} technique={technique} url={url} status={status}", 0.3)
    
    def log_payload_analysis(self, deception_payloads: List[Dict], results: List[Dict]):
        """Log detailed payload analysis"""
        for i, payload in enumerate(deception_payloads, 1):
            description = payload['description']
            url_suffix = payload['url_suffix']
            payload_type = self.get_payload_type(url_suffix)
            payload_size = len(url_suffix.encode('utf-8'))
            
            # Check if successful
            is_successful = any(result['technique'] == description for result in results)
            status = "SUCCESS" if is_successful else "FAILED"
            
            self._log_real_time(f"PAYLOAD_ANALYSIS #{i:02d} type={payload_type} description={description} size={payload_size} status={status}", 0.2)
    
    def log_deception_types(self, results: List[Dict], deception_payloads: List[Dict]):
        """Log deception types breakdown"""
        type_stats = {}
        
        # Count success by type
        for result in results:
            payload_type = self.get_payload_type_from_result(result, deception_payloads)
            if payload_type not in type_stats:
                type_stats[payload_type] = {'success': 0, 'total': 0}
            type_stats[payload_type]['success'] += 1
        
        # Count total by type
        for payload in deception_payloads:
            payload_type = self.get_payload_type(payload['url_suffix'])
            if payload_type not in type_stats:
                type_stats[payload_type] = {'success': 0, 'total': 0}
            type_stats[payload_type]['total'] += 1
        
        for payload_type, stats in type_stats.items():
            success_count = stats['success']
            total_count = stats['total']
            success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
            
            self._log_real_time(f"DECEPTION_TYPE type={payload_type} success={success_count} total={total_count} rate={success_rate:.1f}%", 0.2)
    
    def log_payload_sizes(self, deception_payloads: List[Dict], results: List[Dict]):
        """Log payload size analysis"""
        sizes = [len(p['url_suffix'].encode('utf-8')) for p in deception_payloads]
        avg_size = sum(sizes) / len(sizes)
        min_size = min(sizes)
        max_size = max(sizes)
        
        self._log_real_time(f"PAYLOAD_SIZE_ANALYSIS average={avg_size:.1f} min={min_size} max={max_size}", 0.2)
        
        # Successful payload sizes
        successful_sizes = [len(self.find_payload_by_description(deception_payloads, r['technique'])['url_suffix'].encode('utf-8')) 
                          for r in results if self.find_payload_by_description(deception_payloads, r['technique'])]
        if successful_sizes:
            avg_success_size = sum(successful_sizes) / len(successful_sizes)
            self._log_real_time(f"SUCCESSFUL_PAYLOAD_SIZE average={avg_success_size:.1f}", 0.2)
    
    def log_ready_payloads(self, results: List[Dict], deception_payloads: List[Dict]):
        """Log copy-paste ready payloads"""
        for i, result in enumerate(results, 1):
            technique = result['technique']
            payload = self.find_payload_by_description(deception_payloads, technique)
            
            if payload:
                url_suffix = payload['url_suffix']
                payload_size = len(url_suffix.encode('utf-8'))
                
                self._log_real_time(f"READY_PAYLOAD #{i:02d} technique={technique} payload={url_suffix} size={payload_size}", 0.3)
    
    def log_security_impact(self, results: List[Dict]):
        """Log security impact assessment"""
        impacts = []
        
        # Extension deceptions
        extension_deceptions = sum(1 for r in results if any(ext in r['technique'] for ext in ['.css', '.js', '.png', '.json']))
        if extension_deceptions > 0:
            impacts.append(("STATIC_RESOURCE_DECEPTION", "HIGH"))
        
        # Encoding deceptions
        encoding_deceptions = sum(1 for r in results if any(enc in r['technique'] for enc in ['encoding', 'traversal']))
        if encoding_deceptions > 0:
            impacts.append(("PATH_TRAVERSAL_DECEPTION", "MEDIUM"))
        
        # Parameter deceptions
        param_deceptions = sum(1 for r in results if 'parameter' in r['technique'].lower())
        if param_deceptions > 0:
            impacts.append(("PARAMETER_CACHE_POISONING", "LOW"))
        
        # Fragment deceptions
        fragment_deceptions = sum(1 for r in results if 'fragment' in r['technique'].lower())
        if fragment_deceptions > 0:
            impacts.append(("FRAGMENT_CACHE_ABUSE", "LOW"))
        
        for impact, severity in impacts:
            self._log_real_time(f"SECURITY_IMPACT type={impact} severity={severity}", 0.2)
    
    def log_scan_completion(self, success_rate: float, success_payloads: int, total_payloads: int):
        """Log scan completion"""
        message = f"SCAN_COMPLETED success_rate={success_rate:.1f}% successful={success_payloads}/{total_payloads}"
        self._log_real_time(message, 0.5)
    
    # Helper methods
    def get_deception_type(self, technique):
        """Get deception type from technique description"""
        if any(ext in technique for ext in ['.css', '.js', '.png', '.json']):
            return "EXTENSION_DECEPTION"
        elif any(enc in technique for enc in ['encoding', 'traversal']):
            return "ENCODING_DECEPTION"
        elif 'parameter' in technique.lower():
            return "PARAMETER_DECEPTION"
        elif 'fragment' in technique.lower():
            return "FRAGMENT_DECEPTION"
        else:
            return "GENERIC_DECEPTION"
    
    def get_payload_type(self, url_suffix):
        """Get payload type from URL suffix"""
        if any(ext in url_suffix for ext in ['.css', '.js', '.png', '.json']):
            return "EXTENSION"
        elif any(enc in url_suffix for enc in ['%2e', '..', ';/']):
            return "ENCODING"
        elif '?' in url_suffix:
            return "PARAMETER"
        elif '#' in url_suffix:
            return "FRAGMENT"
        else:
            return "PATH"
    
    def get_payload_type_from_result(self, result, deception_payloads):
        """Get payload type from result"""
        payload = self.find_payload_by_description(deception_payloads, result['technique'])
        if payload:
            return self.get_payload_type(payload['url_suffix'])
        return "UNKNOWN"
    
    def find_payload_by_description(self, deception_payloads, description):
        """Find payload by description"""
        for payload in deception_payloads:
            if payload['description'] == description:
                return payload
        return None
