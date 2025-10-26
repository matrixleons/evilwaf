import time
import datetime
import os
from typing import List, Dict, Any

class SSTILogger:
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
        
        print(f"[{timestamp} {pid}:{thread_id} I/EVILWAF-SSTI] {message}")
        time.sleep(delay)
    
    def log_scan_start(self, domain: str):
        """Log SSTI scan initiation"""
        self._log_real_time(f"SSTI_SCAN_STARTED domain={domain}", 0.3)
    
    def log_statistics(self, total_payloads: int, success_payloads: int, success_rate: float):
        """Log statistical summary"""
        message = (f"STATS total_payloads={total_payloads} "
                  f"success_payloads={success_payloads} "
                  f"success_rate={success_rate:.1f}%")
        self._log_real_time(message, 0.4)
    
    def log_successful_attacks(self, results: List[str]):
        """Log all successful SSTI attacks"""
        for i, attack_name in enumerate(results, 1):
            # Determine engine and technique
            if "Universal" in attack_name:
                engine = "MULTI_ENGINE"
                technique = "POLYGLOT_PAYLOAD"
            elif "Python" in attack_name:
                engine = "JINJA2_TORNADO"
                technique = "CLASS_INSPECTION"
            elif "Java" in attack_name:
                engine = "SPRING_THYMELEAF"
                technique = "EXPRESSION_LANGUAGE"
            elif "Cache" in attack_name:
                engine = "TWIG_SMARTY"
                technique = "DEBUG_EXPLOIT"
            elif "Multi-Engine" in attack_name:
                engine = "JINJA2_SPRING"
                technique = "COMMAND_EXECUTION"
            elif "File Read" in attack_name:
                engine = "JINJA2_SPRING"
                technique = "FILE_SYSTEM_ACCESS"
            elif "Command Chain" in attack_name:
                engine = "JINJA2_FLASK"
                technique = "GLOBALS_EXPLOIT"
            elif "Jinja2" in attack_name:
                engine = "JINJA2"
                technique = "OS_COMMAND_EXEC"
            elif "Twig" in attack_name:
                engine = "TWIG"
                technique = "CALLBACK_EXPLOIT"
            elif "Freemarker" in attack_name:
                engine = "FREEMARKER"
                technique = "TEMPLATE_EXEC"
            else:
                engine = "UNKNOWN"
                technique = "STANDARD_SSTI"
            
            self._log_real_time(f"SUCCESS_ATTACK #{i:02d} name={attack_name} engine={engine} technique={technique}", 0.2)
    
    def log_template_engines(self, results: List[str], success_payloads: int):
        """Log template engine vulnerabilities"""
        engine_counts = {
            'JINJA2_TORNADO': 0,
            'SPRING_THYMELEAF': 0,
            'TWIG_SMARTY': 0,
            'FREEMARKER': 0,
            'MULTI_ENGINE': 0,
            'UNKNOWN': 0
        }
        
        for attack_name in results:
            if "Python" in attack_name or "Jinja2" in attack_name or "Command Chain" in attack_name:
                engine_counts['JINJA2_TORNADO'] += 1
            elif "Java" in attack_name or "Multi-Engine" in attack_name or "File Read" in attack_name:
                engine_counts['SPRING_THYMELEAF'] += 1
            elif "Cache" in attack_name or "Twig" in attack_name:
                engine_counts['TWIG_SMARTY'] += 1
            elif "Freemarker" in attack_name:
                engine_counts['FREEMARKER'] += 1
            elif "Universal" in attack_name:
                engine_counts['MULTI_ENGINE'] += 1
            else:
                engine_counts['UNKNOWN'] += 1
        
        for engine, count in engine_counts.items():
            if count > 0:
                percent = (count / success_payloads) * 100 if success_payloads > 0 else 0
                self._log_real_time(f"ENGINE_VULNERABILITY engine={engine} count={count} percentage={percent:.1f}%", 0.2)
    
    def log_payload_details(self, results: List[str], ssti_payloads: List[str]):
        """Log successful SSTI payload details"""
        for i, attack_name in enumerate(results, 1):
            payload_index = i - 1
            if payload_index < len(ssti_payloads):
                payload = ssti_payloads[payload_index]
                
                # Determine payload type
                if "{{" in payload and "${" in payload and "#{" in payload:
                    payload_type = "UNIVERSAL_POLYGLOT"
                elif "{{" in payload and "__class__" in payload:
                    payload_type = "PYTHON_RCE"
                elif "${" in payload and "T(java.lang" in payload:
                    payload_type = "JAVA_EL_INJECTION"
                elif "{% debug %}" in payload:
                    payload_type = "DEBUG_EXPLOIT"
                elif "popen" in payload and "read()" in payload:
                    payload_type = "COMMAND_EXECUTION"
                elif "/etc/passwd" in payload:
                    payload_type = "FILE_READ_ATTACK"
                elif "__globals__" in payload:
                    payload_type = "GLOBALS_EXPLOIT"
                elif "registerUndefinedFilterCallback" in payload:
                    payload_type = "CALLBACK_EXPLOIT"
                elif "<#assign" in payload:
                    payload_type = "FREEMARKER_RCE"
                else:
                    payload_type = "CUSTOM_PAYLOAD"
                
                # Create payload preview
                payload_preview = payload[:50] + "..." if len(payload) > 50 else payload
                
                self._log_real_time(f"PAYLOAD_DETAILS attack={i} type={payload_type} preview={payload_preview}", 0.3)
    
    def log_technique_effectiveness(self, results: List[str]):
        """Log attack techniques effectiveness"""
        technique_stats = {
            'CODE_EXECUTION': 0,
            'FILE_SYSTEM_ACCESS': 0,
            'CLASS_INSPECTION': 0,
            'COMMAND_INJECTION': 0,
            'DEBUG_EXPLOIT': 0,
            'POLYGLOT_BYPASS': 0
        }
        
        for attack_name in results:
            if "RCE" in attack_name or "exec" in attack_name.lower():
                technique_stats['CODE_EXECUTION'] += 1
            elif "File Read" in attack_name or "/etc/passwd" in attack_name:
                technique_stats['FILE_SYSTEM_ACCESS'] += 1
            elif "Python" in attack_name or "__class__" in attack_name:
                technique_stats['CLASS_INSPECTION'] += 1
            elif "Command" in attack_name or "popen" in attack_name:
                technique_stats['COMMAND_INJECTION'] += 1
            elif "Cache" in attack_name or "debug" in attack_name:
                technique_stats['DEBUG_EXPLOIT'] += 1
            elif "Universal" in attack_name or "Polyglot" in attack_name:
                technique_stats['POLYGLOT_BYPASS'] += 1
        
        for technique, count in technique_stats.items():
            if count > 0:
                impact_level = "CRITICAL" if technique in ['CODE_EXECUTION', 'COMMAND_INJECTION'] else "HIGH" if technique in ['FILE_SYSTEM_ACCESS'] else "MEDIUM"
                self._log_real_time(f"TECHNIQUE_EFFECTIVENESS technique={technique} count={count} impact={impact_level}", 0.2)
    
    def log_security_impact(self, results: List[str]):
        """Log security impact assessment"""
        impacts = []
        
        if any("RCE" in attack for attack in results):
            impacts.append(("REMOTE_CODE_EXECUTION", "CRITICAL"))
        
        if any("File Read" in attack for attack in results):
            impacts.append(("FILE_SYSTEM_ACCESS", "CRITICAL"))
        
        if any("Command" in attack for attack in results):
            impacts.append(("COMMAND_INJECTION", "CRITICAL"))
        
        if any("Java" in attack for attack in results):
            impacts.append(("JAVA_RCE", "HIGH"))
        
        if any("Python" in attack for attack in results):
            impacts.append(("PYTHON_RCE", "HIGH"))
        
        if any("Universal" in attack for attack in results):
            impacts.append(("POLYGLOT_BYPASS", "MEDIUM"))
        
        for impact, level in impacts:
            self._log_real_time(f"SECURITY_IMPACT type={impact} level={level}", 0.2)
    
    def log_scan_completion(self, success_rate: float, success_payloads: int, total_payloads: int):
        """Log scan completion"""
        message = f"SCAN_COMPLETED success_rate={success_rate:.1f}% successful={success_payloads}/{total_payloads}"
        self._log_real_time(message, 0.5)
