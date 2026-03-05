import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

@dataclass
class WAFSignature:
    name: str
    patterns: List[str]
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    response_codes: List[int] = field(default_factory=list)

class WAFDetector:
    def __init__(self):
        self.waf_signatures = self._initialize_waf_signatures()
    
    def _initialize_waf_signatures(self) -> Dict[str, WAFSignature]:
        return {
            'cloudflare': WAFSignature(
                name='Cloudflare',
                patterns=[
                    r'cloudflare',
                    r'cf-ray',
                    r'__cfduid',
                    r'cf-cache-status',
                    r'cf-connecting-ip',
                    r'checking your browser',
                    r'attention required',
                    r'ddos protection by cloudflare'
                ],
                headers={
                    'Server': r'cloudflare',
                    'CF-RAY': r'.*'
                },
                cookies=['__cfduid', '__cflb', '__cf_bm'],
                response_codes=[403, 503, 429]
            ),
            
            'aws_waf': WAFSignature(
                name='AWS WAF',
                patterns=[
                    r'aws waf',
                    r'request blocked',
                    r'awselb/',
                    r'awselb',
                    r'x-amz-id-',
                    r'x-amz-request-id',
                    r'x-amz-cf-id'
                ],
                headers={
                    'Server': r'awselb/.*',
                    'X-Amz-Cf-Id': r'.*',
                    'X-Amz-Cf-Pop': r'.*'
                },
                response_codes=[403, 503]
            ),
            
            'akamai': WAFSignature(
                name='Akamai',
                patterns=[
                    r'akamaighost',
                    r'akamai',
                    r'edgecast',
                    r'ak_bmsc',
                    r'akavpau',
                    r'akamai-transform'
                ],
                headers={
                    'Server': r'akamai',
                    'X-Akamai-Transformed': r'.*',
                    'X-Akamai-Request-BC': r'.*'
                },
                cookies=['ak_bmsc', 'akavpau']
            ),
            
            'imperva': WAFSignature(
                name='Imperva',
                patterns=[
                    r'incapsula',
                    r'imperva',
                    r'visid_incap_',
                    r'incap_ses_',
                    r'x-iinfo',
                    r'x-cdn'
                ],
                headers={
                    'X-Iinfo': r'.*',
                    'X-CDN': r'incapsula',
                    'Server': r'incapsula'
                },
                cookies=['visid_incap_', 'incap_ses_', 'nlbi_']
            ),
            
            'f5_bigip': WAFSignature(
                name='F5 BIG-IP',
                patterns=[
                    r'bigipserver',
                    r'bigip',
                    r'f5',
                    r'x-wa-info',
                    r'barsession',
                    r'last_pass'
                ],
                headers={
                    'Server': r'bigip|f5',
                    'X-WA-Info': r'.*',
                    'X-Powered-By': r'f5'
                },
                cookies=['BIGipServer', 'MRHSession', 'LastMRH_Session']
            ),
            
            'fortiweb': WAFSignature(
                name='FortiWeb',
                patterns=[
                    r'fortiweb',
                    r'fortigate',
                    r'fwb_',
                    r'x-fortiweb-',
                    r'fortinet'
                ],
                headers={
                    'Server': r'fortiweb',
                    'X-FortiWeb-Version': r'.*',
                    'X-Powered-By': r'fortinet'
                }
            ),
            
            'barracuda': WAFSignature(
                name='Barracuda',
                patterns=[
                    r'barracuda',
                    r'barra_counter_session',
                    r'bnids_',
                    r'barracuda_'
                ],
                headers={
                    'Server': r'barracuda',
                    'X-Barracuda-Appearance': r'.*'
                },
                cookies=['barra_counter_session', 'BNI__BARRACUDA_LB_COOKIE']
            ),
            
            'citrix': WAFSignature(
                name='Citrix NetScaler',
                patterns=[
                    r'citrix',
                    r'netscaler',
                    r'ns_af',
                    r'ns_cache',
                    r'czeq='
                ],
                headers={
                    'Server': r'citrix|netscaler',
                    'Cneonction': r'.*',
                    'X-Nitro-Caching': r'.*'
                },
                cookies=['NSC_', 'citrix_ns_id']
            ),
            
            'sucuri': WAFSignature(
                name='Sucuri',
                patterns=[
                    r'sucuri',
                    r'sucuri_cloudproxy',
                    r'x-sucuri-',
                    r'x-sucuri-id',
                    r'access denied - sucuri'
                ],
                headers={
                    'Server': r'sucuri',
                    'X-Sucuri-ID': r'.*',
                    'X-Sucuri-Cache': r'.*'
                },
                cookies=['sucuri_cloudproxy_uuid_']
            ),
            
            'modsecurity': WAFSignature(
                name='ModSecurity',
                patterns=[
                    r'mod_security',
                    r'modsecurity',
                    r'this error was generated by mod_security',
                    r'web server at'
                ],
                headers={
                    'Server': r'mod_security',
                    'X-Mod-Security': r'.*'
                }
            ),
            
            'palo_alto': WAFSignature(
                name='Palo Alto',
                patterns=[
                    r'palo alto',
                    r'vulnerability',
                    r'pan-',
                    r'palosecurity'
                ],
                headers={
                    'Server': r'palo alto',
                    'X-PAN-Verdict': r'.*'
                }
            ),
            
            'radware': WAFSignature(
                name='Radware',
                patterns=[
                    r'radware',
                    r'x-sl-compstate',
                    r'appwall'
                ],
                headers={
                    'Server': r'radware',
                    'X-SL-CompState': r'.*'
                },
                cookies=['AL_SESS', 'AL_SESS_S']
            ),
            
            'alibaba': WAFSignature(
                name='Alibaba Cloud',
                patterns=[
                    r'aliyun',
                    r'alibaba',
                    r'via: alibaba',
                    r'x-alibaba-',
                    r'x-dispatch-node'
                ],
                headers={
                    'Server': r'aliyun',
                    'X-Powered-By': r'alibaba',
                    'Via': r'alibaba'
                }
            ),
            
            'azure': WAFSignature(
                name='Microsoft Azure',
                patterns=[
                    r'azure',
                    r'microsoft',
                    r'waws',
                    r'arr/',
                    r'arrafinity'
                ],
                headers={
                    'Server': r'waws|arr',
                    'X-Powered-By': r'azure',
                    'X-AspNet-Version': r'.*'
                },
                cookies=['ARRAffinity', 'ARRAffinitySameSite']
            ),
            
            'wordfence': WAFSignature(
                name='Wordfence',
                patterns=[
                    r'wordfence',
                    r'wftoken',
                    r'wf_',
                    r'generated by wordfence'
                ],
                headers={
                    'X-Wordfence-': r'.*'
                },
                cookies=['wfwaf-authcookie', 'wordfence_verifiedHuman']
            ),
            
            'comodo': WAFSignature(
                name='Comodo',
                patterns=[
                    r'comodo',
                    r'protected by comodo',
                    r'cmdwaf'
                ],
                headers={
                    'Server': r'comodo',
                    'X-Protected-By': r'comodo'
                }
            ),
            
            'google_cloud_armor': WAFSignature(
                name='Google Cloud Armor',
                patterns=[
                    r'google cloud armor',
                    r'gce-',
                    r'goog-',
                    r'x-goog-',
                    r'gfe',
                    r'google-cloud-armor'
                ],
                headers={
                    'Server': r'gfe|google',
                    'X-Goog-': r'.*',
                    'Via': r'.*google'
                },
                response_codes=[403, 429]
            ),
            
            'fastly': WAFSignature(
                name='Fastly',
                patterns=[
                    r'fastly',
                    r'x-fastly-',
                    r'fastly-',
                    r'x-served-by.*fastly'
                ],
                headers={
                    'X-Fastly-Request-ID': r'.*',
                    'X-Served-By': r'.*fastly.*',
                    'Via': r'.*fastly.*'
                },
                response_codes=[403, 429]
            ),
            
            'cloudfront': WAFSignature(
                name='AWS CloudFront',
                patterns=[
                    r'cloudfront',
                    r'x-amz-cf-',
                    r'x-cache.*cloudfront'
                ],
                headers={
                    'X-Amz-Cf-Id': r'.*',
                    'X-Amz-Cf-Pop': r'.*',
                    'Via': r'.*cloudfront.*',
                    'X-Cache': r'.*cloudfront.*'
                },
                response_codes=[403]
            ),
            
            'datadome': WAFSignature(
                name='DataDome',
                patterns=[
                    r'datadome',
                    r'dd-',
                    r'datadome\.co',
                    r'x-datadome'
                ],
                headers={
                    'Server': r'datadome',
                    'X-DataDome': r'.*',
                    'X-DD-': r'.*'
                },
                cookies=['datadome'],
                response_codes=[403]
            ),
            
            'ovh': WAFSignature(
                name='OVH',
                patterns=[
                    r'ovh',
                    r'x-ovh-',
                    r'ovhcdn'
                ],
                headers={
                    'Server': r'ovh',
                    'X-OVH-': r'.*',
                    'X-CDN': r'ovh'
                }
            ),
            
            'oracle_cloud': WAFSignature(
                name='Oracle Cloud',
                patterns=[
                    r'oracle',
                    r'x-oracle-',
                    r'oraclecloud'
                ],
                headers={
                    'Server': r'oracle',
                    'X-Oracle-DMS-ECID': r'.*',
                    'X-Oracle-DMS-RID': r'.*'
                },
                response_codes=[403]
            ),
            
            'openappsec': WAFSignature(
                name='OpenAppSec',
                patterns=[
                    r'openappsec',
                    r'open-appsec',
                    r'x-openappsec'
                ],
                headers={
                    'X-OpenAppSec': r'.*',
                    'Server': r'openappsec'
                },
                response_codes=[403]
            ),
            
            'nginx': WAFSignature(
                name='NGINX',
                patterns=[
                    r'nginx',
                    r'x-nginx'
                ],
                headers={
                    'Server': r'nginx',
                    'X-Powered-By': r'nginx'
                }
            ),
            
            'apache': WAFSignature(
                name='Apache',
                patterns=[
                    r'apache',
                    r'x-apache'
                ],
                headers={
                    'Server': r'apache',
                    'X-Powered-By': r'apache'
                }
            ),
            
            'zip': WAFSignature(
                name='ZScaler',
                patterns=[
                    r'zscaler',
                    r'x-zscaler-',
                    r'zen\.zscaler'
                ],
                headers={
                    'X-Zscaler-': r'.*',
                    'Server': r'zscaler'
                },
                response_codes=[403]
            ),
            
            'shield': WAFSignature(
                name='Shield Security',
                patterns=[
                    r'shield security',
                    r'shield-security',
                    r'icwp-wpsf'
                ],
                headers={
                    'X-Shield-': r'.*'
                },
                cookies=['icwp-wpsf']
            ),
            
            'fraudlabs': WAFSignature(
                name='FraudLabs Pro',
                patterns=[
                    r'fraudlabs',
                    r'fraudlabspro',
                    r'x-fraudlabs'
                ],
                headers={
                    'X-FraudLabsPro-': r'.*',
                    'Server': r'fraudlabs'
                }
            ),
            
            'litespeed': WAFSignature(
                name='LiteSpeed',
                patterns=[
                    r'litespeed',
                    r'x-litespeed-',
                    r'lsws'
                ],
                headers={
                    'Server': r'litespeed|lsws',
                    'X-LiteSpeed-Cache': r'.*',
                    'X-Powered-By': r'litespeed'
                }
            ),
            
            'openlitespeed': WAFSignature(
                name='OpenLiteSpeed',
                patterns=[
                    r'openlitespeed',
                    r'x-litespeed-',
                    r'ols/'
                ],
                headers={
                    'Server': r'openlitespeed',
                    'X-Powered-By': r'openlitespeed'
                }
            ),
            
            'kubernetes': WAFSignature(
                name='Kubernetes Ingress',
                patterns=[
                    r'kubernetes',
                    r'ingress-nginx',
                    r'x-request-id'
                ],
                headers={
                    'Server': r'kubernetes|ingress',
                    'X-Request-ID': r'.*'
                }
            ),
            
            'varnish': WAFSignature(
                name='Varnish',
                patterns=[
                    r'varnish',
                    r'x-varnish',
                    r'x-cache.*varnish'
                ],
                headers={
                    'Server': r'varnish',
                    'X-Varnish': r'.*',
                    'Via': r'.*varnish.*',
                    'X-Cache': r'.*varnish.*'
                }
            ),
            
            'envoy': WAFSignature(
                name='Envoy Proxy',
                patterns=[
                    r'envoy',
                    r'x-envoy-'
                ],
                headers={
                    'Server': r'envoy',
                    'X-Envoy-': r'.*'
                }
            ),
            
            'liquid': WAFSignature(
                name='Liquid Web',
                patterns=[
                    r'liquid web',
                    r'liquidweb',
                    r'x-lw-'
                ],
                headers={
                    'Server': r'liquid.*web',
                    'X-LW-': r'.*'
                }
            ),
            
            'kong': WAFSignature(
                name='Kong Gateway',
                patterns=[
                    r'kong',
                    r'x-kong-',
                    r'kong/'
                ],
                headers={
                    'Server': r'kong',
                    'X-Kong-': r'.*',
                    'Via': r'kong'
                }
            ),
            
            'fortinet': WAFSignature(
                name='Fortinet',
                patterns=[
                    r'fortinet',
                    r'fortigate',
                    r'x-forti'
                ],
                headers={
                    'Server': r'fortinet',
                    'X-Forti': r'.*'
                },
                response_codes=[403]
            ),
            
            'microsoft_iis': WAFSignature(
                name='Microsoft IIS',
                patterns=[
                    r'microsoft-iis',
                    r'iis/',
                    r'x-powered-by: asp.net'
                ],
                headers={
                    'Server': r'microsoft-iis',
                    'X-Powered-By': r'asp\.net',
                    'X-AspNet-Version': r'.*'
                }
            ),
            
            'siteground': WAFSignature(
                name='SiteGround',
                patterns=[
                    r'siteground',
                    r'sg-optimizer',
                    r'x-sg-'
                ],
                headers={
                    'Server': r'siteground',
                    'X-SG-': r'.*'
                }
            ),
            
            'openresty': WAFSignature(
                name='OpenResty',
                patterns=[
                    r'openresty',
                    r'x-openresty'
                ],
                headers={
                    'Server': r'openresty',
                    'X-Powered-By': r'openresty'
                }
            ),
            
            'malcare': WAFSignature(
                name='MalCare',
                patterns=[
                    r'malcare',
                    r'x-malcare',
                    r'protected by malcare'
                ],
                headers={
                    'X-MalCare': r'.*'
                },
                response_codes=[403]
            ),
            
            'lua_resty_waf': WAFSignature(
                name='Lua Resty WAF',
                patterns=[
                    r'lua-resty-waf',
                    r'resty-waf',
                    r'x-lua-waf'
                ],
                headers={
                    'X-Lua-WAF': r'.*',
                    'Server': r'.*lua.*'
                }
            ),
            
            'wildfly_waf': WAFSignature(
                name='WildFly',
                patterns=[
                    r'wildfly',
                    r'jboss',
                    r'x-powered-by.*wildfly'
                ],
                headers={
                    'Server': r'wildfly|jboss',
                    'X-Powered-By': r'wildfly|jboss'
                }
            ),
            
            'watchguard': WAFSignature(
                name='WatchGuard',
                patterns=[
                    r'watchguard',
                    r'wg-',
                    r'x-wg-'
                ],
                headers={
                    'Server': r'watchguard',
                    'X-WG-': r'.*'
                },
                response_codes=[403]
            ),
            
            'sonicwall': WAFSignature(
                name='SonicWall',
                patterns=[
                    r'sonicwall',
                    r'sonewall',
                    r'x-sonicwall-'
                ],
                headers={
                    'Server': r'sonicwall',
                    'X-SonicWall-': r'.*'
                },
                response_codes=[403]
            ),
            
            'hetzner': WAFSignature(
                name='Hetzner',
                patterns=[
                    r'hetzner',
                    r'x-hetzner-',
                    r'hetzner-cloud'
                ],
                headers={
                    'Server': r'hetzner',
                    'X-Hetzner-': r'.*'
                }
            ),
            
            'cloudways': WAFSignature(
                name='Cloudways',
                patterns=[
                    r'cloudways',
                    r'x-cloudways-',
                    r'cw-'
                ],
                headers={
                    'Server': r'cloudways',
                    'X-Cloudways-': r'.*',
                    'X-CW-': r'.*'
                }
            )
        }
    
    def detect_from_headers(self, headers: Dict[str, str]) -> List[str]:
        detected_wafs = []
        
        for waf_id, signature in self.waf_signatures.items():
            if self._check_headers_match(headers, signature):
                detected_wafs.append(signature.name)
        
        return detected_wafs
    
    def detect_from_response(self, response_body: str, headers: Dict[str, str] = None) -> List[str]:
        detected_wafs = []
        
        for waf_id, signature in self.waf_signatures.items():
            if self._check_response_match(response_body, headers or {}, signature):
                detected_wafs.append(signature.name)
        
        return detected_wafs
    
    def detect_from_cookies(self, cookies: Dict[str, str]) -> List[str]:
        detected_wafs = []
        
        for waf_id, signature in self.waf_signatures.items():
            if signature.cookies:
                for cookie_name in cookies.keys():
                    if any(cookie_pattern in cookie_name.lower() for cookie_pattern in signature.cookies):
                        detected_wafs.append(signature.name)
                        break
        
        return detected_wafs
    
    def detect_all(self, 
                  response_body: str = "", 
                  headers: Dict[str, str] = None,
                  cookies: Dict[str, str] = None,
                  status_code: int = None) -> List[str]:
        detected_wafs = set()
        
        if headers:
            detected_wafs.update(self.detect_from_headers(headers))
        
        if response_body:
            detected_wafs.update(self.detect_from_response(response_body, headers or {}))
        
        if cookies:
            detected_wafs.update(self.detect_from_cookies(cookies))
        
        if status_code:
            detected_wafs.update(self.detect_from_status_code(status_code))
        
        return list(detected_wafs)
    
    def detect_from_status_code(self, status_code: int) -> List[str]:
        detected_wafs = []
        
        for waf_id, signature in self.waf_signatures.items():
            if signature.response_codes and status_code in signature.response_codes:
                detected_wafs.append(signature.name)
        
        return detected_wafs
    
    def _check_headers_match(self, headers: Dict[str, str], signature: WAFSignature) -> bool:
        for header_name, header_pattern in signature.headers.items():
            for actual_header, actual_value in headers.items():
                if header_name.lower() in actual_header.lower():
                    if re.search(header_pattern, actual_value, re.IGNORECASE):
                        return True
        
        return False
    
    def _check_response_match(self, response_body: str, headers: Dict[str, str], signature: WAFSignature) -> bool:
        response_lower = response_body.lower()
        
        for pattern in signature.patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                return True
        
        for header_name, header_pattern in signature.headers.items():
            for actual_header, actual_value in headers.items():
                if header_name.lower() in actual_header.lower():
                    if re.search(header_pattern, actual_value, re.IGNORECASE):
                        return True
        
        return False
    
    def get_waf_info(self, waf_name: str) -> Optional[Dict]:
        for waf_id, signature in self.waf_signatures.items():
            if signature.name.lower() == waf_name.lower() or waf_id.lower() == waf_name.lower():
                return {
                    'id': waf_id,
                    'name': signature.name,
                    'patterns': signature.patterns,
                    'headers': signature.headers,
                    'cookies': signature.cookies,
                    'response_codes': signature.response_codes
                }
        return None
    
    def list_all_wafs(self) -> List[str]:
        return [signature.name for signature in self.waf_signatures.values()]
    
    def get_signature_count(self) -> int:
        return len(self.waf_signatures)
    
    def add_custom_signature(self, 
                           waf_id: str, 
                           name: str, 
                           patterns: List[str], 
                           headers: Dict[str, str] = None,
                           cookies: List[str] = None,
                           response_codes: List[int] = None):
        self.waf_signatures[waf_id] = WAFSignature(
            name=name,
            patterns=patterns,
            headers=headers or {},
            cookies=cookies or [],
            response_codes=response_codes or []
        )
    
    def remove_signature(self, waf_id: str) -> bool:
        if waf_id in self.waf_signatures:
            del self.waf_signatures[waf_id]
            return True
        return False
    
    def search_pattern(self, pattern: str) -> List[Tuple[str, str]]:
        results = []
        pattern_lower = pattern.lower()
        
        for waf_id, signature in self.waf_signatures.items():
            for sig_pattern in signature.patterns:
                if pattern_lower in sig_pattern.lower():
                    results.append((signature.name, sig_pattern))
            
            for header_pattern in signature.headers.values():
                if pattern_lower in header_pattern.lower():
                    results.append((signature.name, f"Header: {header_pattern}"))
            
            for cookie_pattern in signature.cookies:
                if pattern_lower in cookie_pattern.lower():
                    results.append((signature.name, f"Cookie: {cookie_pattern}"))
        
        return results