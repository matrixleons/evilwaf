import time
import datetime
import os
import re
from typing import List, Dict, Any

class GraphQLLogger:
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
        
        print(f"[{timestamp} {pid}:{thread_id} I/EVILWAF-GRAPHQL] {message}")
        time.sleep(delay)
    
    def log_scan_start(self, domain: str):
        """Log GraphQL scan initiation"""
        self._log_real_time(f"GRAPHQL_SCAN_STARTED domain={domain}", 0.3)
    
    def log_statistics(self, total_payloads: int, success_payloads: int, success_rate: float):
        """Log statistical summary"""
        message = (f"STATS total_payloads={total_payloads} "
                  f"success_payloads={success_payloads} "
                  f"success_rate={success_rate:.1f}%")
        self._log_real_time(message, 0.4)
    
    def log_successful_queries(self, working_queries: List[Dict]):
        """Log all successful GraphQL queries"""
        for i, query_data in enumerate(working_queries, 1):
            payload = query_data.get('payload', {})
            endpoint = query_data.get('endpoint', 'Unknown')
            
            # Determine attack type
            if isinstance(payload, list):
                if any("UNION SELECT" in str(q.get('query', '')) for q in payload):
                    attack_type = "SQL_INJECTION_BATCHING"
                elif any("mutation" in str(q.get('query', '')).lower() for q in payload):
                    attack_type = "MUTATION_BATCHING"
                else:
                    attack_type = "QUERY_BATCHING"
            else:
                query_str = str(payload.get('query', ''))
                if "__schema" in query_str:
                    attack_type = "INTROSPECTION_ATTACK"
                elif "UNION SELECT" in query_str:
                    attack_type = "SQL_INJECTION"
                elif "aliasing" in query_str.lower() or "normal:" in query_str:
                    attack_type = "ALIASING_ATTACK"
                elif "variables" in payload:
                    attack_type = "VARIABLES_BATCHING"
                else:
                    attack_type = "STANDARD_QUERY"
            
            self._log_real_time(f"SUCCESS_QUERY #{i:02d} type={attack_type} endpoint={endpoint}", 0.2)
    
    def log_vulnerable_endpoints(self, working_queries: List[Dict]):
        """Log vulnerable GraphQL endpoints"""
        endpoints_found = list(set([q.get('endpoint', 'Unknown') for q in working_queries]))
        
        for endpoint in endpoints_found:
            count = sum(1 for q in working_queries if q.get('endpoint') == endpoint)
            self._log_real_time(f"VULNERABLE_ENDPOINT endpoint={endpoint} success_count={count}", 0.2)
    
    def log_attack_categories(self, category_counts: Dict[str, int], success_payloads: int):
        """Log attack categories breakdown"""
        for category, count in category_counts.items():
            percent = (count / success_payloads) * 100 if success_payloads > 0 else 0
            self._log_real_time(f"CATEGORY {category.replace(' ', '_').upper()} count={count} percentage={percent:.1f}%", 0.2)
    
    def log_data_leakage(self, working_queries: List[Dict]):
        """Log sensitive data found in responses"""
        data_found = False
        
        for i, query_data in enumerate(working_queries, 1):
            response = query_data.get('response_preview', '')
            
            # Extract emails
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, response)
            
            # Extract JWT tokens
            token_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*'
            tokens = re.findall(token_pattern, response)
            
            # Extract passwords
            password_pattern = r'"password"\s*:\s*"([^"]+)"|\'password\'\s*:\s*\'([^\']+)\''
            passwords = re.findall(password_pattern, response)
            passwords = [p for tuple_item in passwords for p in tuple_item if p]
            
            # Extract admin data
            admin_pattern = r'"admin"\s*:\s*(true|false)|"role"\s*:\s*"([^"]+)"|"isAdmin"\s*:\s*(true|false)'
            admin_data = re.findall(admin_pattern, response)
            admin_data = [item for tuple_item in admin_data for item in tuple_item if item]
            
            # Extract user data
            user_pattern = r'"id"\s*:\s*"([^"]+)"|"username"\s*:\s*"([^"]+)"|"name"\s*:\s*"([^"]+)"'
            users = re.findall(user_pattern, response)
            users = [item for tuple_item in users for item in tuple_item if item]
            
            # Log found data
            if emails:
                for email in emails[:2]:
                    self._log_real_time(f"DATA_LEAKED query={i} type=EMAIL value={email}", 0.1)
                    data_found = True
            
            if tokens:
                for token in tokens[:2]:
                    token_preview = token[:35] + "..." if len(token) > 35 else token
                    self._log_real_time(f"DATA_LEAKED query={i} type=JWT_TOKEN value={token_preview}", 0.1)
                    data_found = True
            
            if passwords:
                for password in passwords[:2]:
                    password_preview = password[:35] + "..." if len(password) > 35 else password
                    self._log_real_time(f"DATA_LEAKED query={i} type=PASSWORD value={password_preview}", 0.1)
                    data_found = True
            
            if admin_data:
                for admin_item in admin_data[:2]:
                    self._log_real_time(f"DATA_LEAKED query={i} type=ADMIN_DATA value={admin_item}", 0.1)
                    data_found = True
            
            if users:
                for user in users[:2]:
                    self._log_real_time(f"DATA_LEAKED query={i} type=USER_DATA value={user}", 0.1)
                    data_found = True
        
        if not data_found:
            self._log_real_time("DATA_LEAKAGE no_sensitive_data_found", 0.2)
    
    def log_scan_completion(self, success_rate: float, success_payloads: int, total_payloads: int):
        """Log scan completion"""
        message = f"SCAN_COMPLETED success_rate={success_rate:.1f}% successful={success_payloads}/{total_payloads}"
        self._log_real_time(message, 0.5)
