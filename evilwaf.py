#!/usr/bin/env python3
"""
EVILWAF - Firewall Bypass Tool

STRICT LEGAL DISCLAIMER:
    This program is designed for educational purposes only, especially for legal security testing.
    Users must have explicit permission before testing any system. Unauthorized access is illegal.
    The developer is not responsible for any misuse or violations caused by this tool.

INTENDED USES:
    • Ethical hacking and penetration testing
    • Authorized security research
    • Educational cybersecurity training
    • Legitimate bug bounty programs

CREATED BY: Matrix Leons
CONTACT: codeleons724@gmail.com
Copyright (c) 2025 Matrix Leons. All rights reserved.

         Happy ethical hacking!

"""

import argparse
import asyncio
import aiohttp
import dns.resolver
import socket
import ssl
import re
import json
import random
import sys
import time
from core.updater import EvilWAFUpdater
# ========================================




class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def show_banner():
    banner = f"""
{Colors.BLUE}
___________     .__.__                  _____ 
\\_   _____/__  _|__|  |__  _  _______ _/ ____\\
 |    __)_\\  \\/ /  |  |\\ \\/ \\/ /\\__  \\\\   __\\ 
 |        \\\\   /|  |  |_\\     /  / __ \\|  |   
/_______  / \\_/ |__|____/\\/\\_/  (____  /__|   
        \\/                           \\/       

{Colors.WHITE}
            EVILWAF - Firewall bypass tool

  Created by: Matrix.                                            Version 2.0

                          Codename : hack error 404                 

{Colors.END}
"""
    print(banner)

#firewall patterns will be updated to make firewall detection better...... 
#



class FirewallDetector:
    def __init__(self):
        self.firewall_patterns = {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cloudflare'],
                'ips': ['104.16.0.0/12', '172.64.0.0/13', '173.245.48.0/20']
            },
            'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', 'cloudflare', 'cf-connecting-ip', 'cf-ipcountry', 'cf-request-id', '__cfduid'],
            'ips': ['104.16.0.0/12', '172.64.0.0/13', '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '172.64.0.0/13', '131.0.72.0/22']
            },  
            'akamai': {
            'headers': ['x-akamai-transformed', 'akamai', 'akamaiedge', 'akamai-ghost', 'x-akamai-request-id', 'akamai-origin-hop'],
            'ips': ['23.0.0.0/12', '23.192.0.0/11', '2.16.0.0/13', '184.24.0.0/13', '184.50.0.0/15', '184.84.0.0/14', '23.32.0.0/11', '72.246.0.0/15', '88.221.0.0/16', '96.6.0.0/15', '104.64.0.0/10', '184.26.0.0/15', '184.86.0.0/16', '23.74.0.0/15', '95.100.0.0/15']
            },
            'aws_waf': {
            'headers': ['x-amz-cf-pop', 'x-amz-cf-id', 'x-amzn-requestid', 'x-amz-request-id', 'awselb', 'x-amzn-trace-id'],
            'ips': ['3.0.0.0/9', '13.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8', '15.0.0.0/8', '18.0.0.0/8', '35.0.0.0/8', '44.0.0.0/8', '52.95.0.0/16', '54.240.0.0/16', '99.77.0.0/16', '99.78.0.0/16', '150.222.0.0/16', '205.251.192.0/19'] 
            },
            'azure_waf': {
            'headers': ['x-azure-ref', 'x-azure-origin', 'x-azure-fdid', 'x-ms-request-id', 'x-powered-by-plesk'],
            'ips': ['20.0.0.0/8', '40.0.0.0/8', '52.0.0.0/8', '104.40.0.0/12', '13.64.0.0/11', '13.96.0.0/13', '40.112.0.0/13', '40.120.0.0/14', '52.160.0.0/11', '65.52.0.0/14', '70.37.0.0/17', '104.40.0.0/13', '104.146.0.0/16', '137.116.0.0/15', '168.61.0.0/16']
            },
            'google_cloud_armor': {
            'headers': ['x-google-cloud-armor', 'x-goog-request-reason', 'gws', 'x-cloud-trace-context', 'x-goog-request-log-name', 'gcp-loadbalancer'],
            'ips': ['8.0.0.0/8', '34.0.0.0/8', '35.0.0.0/8', '104.0.0.0/8', '107.178.0.0/15', '108.170.0.0/15', '108.177.0.0/15', '130.211.0.0/16', '142.250.0.0/15', '146.148.0.0/16', '162.216.0.0/15', '162.222.0.0/15', '172.217.0.0/15', '172.253.0.0/15', '173.194.0.0/15', '192.158.0.0/15', '199.192.0.0/14', '199.223.0.0/15', '209.85.0.0/15']
            },
            'fastly': {
            'headers': ['fastly', 'x-served-by', 'x-cache', 'x-timer', 'fastly-debug-digest', 'x-fastly-request-id'],
            'ips': ['23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '104.156.80.0/20', '146.75.0.0/16', '151.101.0.0/16', '157.52.0.0/16', '167.82.0.0/17', '172.111.64.0/18', '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16']
            },
            'imperva': {
            'headers': ['imperva', 'x-iinfo', 'incap_ses', 'visid_incap', 'x-imperva-client', 'x-imperva-backend'],
            'ips': ['199.83.128.0/21', '198.143.32.0/19', '45.60.0.0/16', '45.223.0.0/16', '185.11.124.0/22', '192.230.64.0/18', '107.154.0.0/16', '45.35.0.0/16', '45.64.0.0/16', '185.234.0.0/16']
            },
            'sucuri': {
            'headers': ['sucuri', 'x-sucuri-id', 'x-sucuri-cache', 'cloudproxy', 'x-sucuri-block'],
            'ips': ['192.124.249.0/24', '192.161.0.0/24', '192.169.0.0/24', '198.58.0.0/16', '198.100.0.0/16', '199.167.0.0/16', '205.164.0.0/16']
            },
            'cloudfront': {
            'headers': ['cloudfront', 'x-amz-cf-id', 'via', 'x-amz-cf-pop'],
            'ips': ['13.32.0.0/15', '13.54.0.0/15', '13.224.0.0/14', '34.216.0.0/14', '35.182.0.0/15', '52.46.0.0/18', '52.84.0.0/15', '52.124.0.0/16', '52.222.0.0/17', '54.182.0.0/16', '54.192.0.0/16', '54.230.0.0/16', '54.239.128.0/18', '58.254.138.0/25', '64.252.64.0/18', '70.132.0.0/18', '71.152.0.0/17', '99.84.0.0/16', '103.4.8.0/22', '120.52.22.96/27', '130.176.0.0/17', '143.204.0.0/16', '144.220.0.0/16', '205.251.192.0/19', '205.251.249.0/24']
            },
            'f5_big_ip': {
            'headers': ['big-ip', 'f5', 'x-waf-event-info', 'bigipserver', 'x-forwarded-for', 'x-forwarded-proto'],
            'ips': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']  # Typically internal IPs
        # 
        
            },
            'barracuda': {
            'headers': ['barracuda', 'barra', 'x-barracuda', 'x-barracuda-appliance'],
            'ips': []  # Custom deployments
            },
            'fortinet': {
            'headers': ['fortinet', 'fortigate', 'x-fortigate-hostname', 'x-fortigate-client'],
            'ips': []  # Custom deployments
            },
            'citrix_netscaler': {
            'headers': ['citrix', 'x-citrix', 'ns_af', 'x-citrix-appliance'],
            'ips': []  # Custom deployments
            },
            'palo_alto': {
            'headers': ['palo alto', 'x-pan', 'x-palo-alto-firewall'],
            'ips': []  # Custom deployments 
            },
            'keycdn': {
            'headers': ['keycdn', 'x-edge-result', 'x-edge-cache', 'x-keycdn-origin'],
            'ips': ['103.214.112.0/22', '103.253.60.0/22', '104.238.128.0/22', '107.191.48.0/22', '109.239.140.0/24', '136.243.128.0/22', '144.76.0.0/19', '148.251.128.0/20', '164.138.128.0/20', '176.9.128.0/20', '185.182.112.0/22', '188.138.0.0/19', '195.201.0.0/19']
        # 
        
            },
              'stackpath': {
            'headers': ['stackpath', 'maxcdn', 'x-sp-url', 'netdna-ssl', 'x-sp-client'],
            'ips': ['151.139.0.0/16', '198.252.108.0/22', '104.156.80.0/20', '107.191.48.0/22', '146.88.128.0/20', '172.111.64.0/18', '185.31.16.0/22', '199.60.0.0/20']
            },
            'bunnycdn': {
            'headers': ['bunnycdn', 'x-bunny-log-id', 'x-pullzone-id', 'x-bunny-server'],
            'ips': ['159.100.351.0/24', '45.134.144.0/24', '89.187.160.0/24', '103.233.192.0/24', '185.234.0.0/24', '194.87.0.0/24']
            },
            'cdn77': {
            'headers': ['cdn77', 'x-77-pop', 'x-cdn77-origin'],
            'ips': ['185.151.28.0/22', '185.224.0.0/22', '193.188.0.0/22', '194.110.0.0/22', '195.181.0.0/22']
            },
            'godaddy': {
            'headers': ['godaddy', 'x-godaddy', 'x-godaddy-proxy'],
            'ips': ['31.222.116.0/24', '50.63.202.0/24', '97.74.0.0/16', '173.201.0.0/16', '184.168.0.0/16', '198.71.0.0/16', '208.109.0.0/16']
        # 
        
            },
            'siteground': {
            'headers': ['siteground', 'x-siteground', 'x-siteground-proxy'],
            'ips': ['35.214.0.0/16', '35.241.0.0/16', '107.180.0.0/16', '162.159.0.0/16', '172.105.0.0/16'] 
            },
            'wpengine': {
            'headers': ['wpengine', 'x-wpengine', 'x-wpe-backend'],
            'ips': ['35.196.0.0/16', '104.196.0.0/16', '162.222.0.0/16', '192.0.96.0/20']
            },
            'alibaba_cloud': {
            'headers': ['alibaba', 'ali-cdn', 'eagleid', 'x-readtime', 'x-alibaba-cloud'],
            'ips': ['47.0.0.0/8', '106.11.0.0/16', '118.31.0.0/16', '120.27.0.0/16', '121.43.0.0/16', '139.196.0.0/16', '182.92.0.0/16']
        # 
        
            },
            'tencent_cloud': {
            'headers': ['tencent', 'x-oss-request-id', 'x-tencent-cloud'],
            'ips': ['119.28.0.0/16', '129.211.0.0/16', '139.199.0.0/16', '150.109.0.0/16', '162.14.0.0/16']
            },
            'huawei_cloud': {
            'headers': ['huawei', 'huaweicloud', 'x-hw-id', 'x-huawei-cloud'],
            'ips': ['117.78.0.0/18', '121.36.0.0/14', '139.9.0.0/16', '159.138.0.0/16', '182.92.0.0/16']
            },
            'nginx': {
            'headers': ['nginx', 'x-nginx', 'x-accel', 'server: nginx'],
            'ips': []  # Custom deployments
        # 
        
            },
            'haproxy': {
            'headers': ['haproxy', 'x-haproxy', 'x-haproxy-server'],
            'ips': []  # Custom deployments
            },
            'varnish': {
            'headers': ['varnish', 'x-varnish', 'x-cache', 'server: varnish'],
            'ips': []  # Custom deployments
            },
            'wordfence': {
            'headers': ['wordfence', 'x-wordfence-blocked', 'x-wordfence-firewall'],
            'ips': []  # Plugin-based, no specific IP ranges
        # 
        
            },
            'sucuri_waf': {
            'headers': ['sucuri', 'x-sucuri-filter', 'x-sucuri-block'],
            'ips': ['192.88.134.0/23', '185.93.228.0/22', '192.169.0.0/16']
            },
            'kong': {
            'headers': ['kong', 'x-kong-upstream-latency', 'x-kong-proxy'],
            'ips': []  # Custom deployments
        # 
        
            },
            'modsecurity': {
            'headers': ['mod_security', 'modsecurity', 'web application firewall'],
            'ips': []  # Software-based
        # 
        
            },
            'datadome': {
            'headers': ['datadome', 'x-datadome', 'dd_', 'x-datadome-client'],
            'ips': ['35.180.0.0/16', '52.47.0.0/16', '54.93.0.0/16', '13.32.0.0/15', '13.224.0.0/14']
        # 
        
            },
            'perimeterx': {
            'headers': ['perimeterx', '_px', 'x-px', 'x-px-authorization'],
            'ips': ['52.28.0.0/16', '52.57.0.0/16', '52.208.0.0/16', '54.93.0.0/16'] 
            },
            'cloudflare_waf': {
            'headers': ['cf-waf', 'cf-firewall', 'x-cf-firewall'],
            'ips': ['104.16.0.0/12', '172.64.0.0/13', '173.245.48.0/20']  # Same as Cloudflare
            },
            'aws_shield': {
            'headers': ['aws-shield', 'x-aws-shield'],
            'ips': ['3.0.0.0/9', '13.0.0.0/8', '52.0.0.0/8']  # Same as AWS WAF
            },
            'oracle_cloud': {
            'headers': ['x-oracle', 'oracle.com', 'x-oci-compartment-id', 'x-oci-request-id'],
            'ips': ['129.213.0.0/16', '132.145.0.0/16', '134.70.0.0/16', '138.1.0.0/16', '140.91.0.0/16', '147.154.0.0/16', '150.136.0.0/16', '152.67.0.0/16', '158.101.0.0/16', '160.1.0.0/16', '192.29.0.0/16']
            },
            'baidu_cloud': {
            'headers': ['baidu', 'x-bce-request-id', 'x-baidu-logid', 'x-bce-content-sha256'],
            'ips': ['220.181.0.0/16', '123.125.0.0/16', '61.135.0.0/16', '180.76.0.0/16', '39.156.0.0/16', '103.235.44.0/22', '119.3.0.0/16']
            },
            'digitalocean': {
            'headers': ['digitalocean', 'do-app-origin', 'x-do-app-origin', 'x-digitalocean-ip'],
            'ips': ['104.131.0.0/16', '104.236.0.0/16', '138.197.0.0/16', '138.68.0.0/16', '139.59.0.0/16', '142.93.0.0/16', '143.198.0.0/16', '147.182.0.0/16', '157.230.0.0/16', '159.65.0.0/16', '159.89.0.0/16', '161.35.0.0/16', '164.90.0.0/16', '165.227.0.0/16', '167.71.0.0/16', '167.99.0.0/16', '174.138.0.0/16', '178.62.0.0/16', '188.166.0.0/16', '188.226.0.0/16', '192.241.0.0/16', '198.199.0.0/16', '198.211.0.0/16', '206.189.0.0/16', '207.154.0.0/16', '209.97.0.0/16', '68.183.0.0/16', '82.196.0.0/16', '95.85.0.0/16']
        # 
        
            },
            'linode': {
            'headers': ['linode', 'x-linode-id', 'x-linode-request-id', 'x-akamai-edgescape'],
            'ips': ['45.33.0.0/16', '45.56.0.0/16', '45.79.0.0/16', '50.116.0.0/16', '66.175.208.0/20', '66.228.32.0/19', '69.46.64.0/18', '69.164.192.0/19', '74.207.224.0/19', '75.127.0.0/17', '96.126.96.0/19', '97.107.128.0/18', '103.3.60.0/22', '106.187.32.0/19', '139.162.0.0/16', '172.104.0.0/15', '172.233.0.0/16', '173.230.128.0/17', '173.255.128.0/17', '176.58.0.0/15', '178.79.128.0/17', '185.3.92.0/22', '192.46.208.0/20', '192.81.128.0/17', '192.155.80.0/20', '198.58.96.0/19', '212.71.232.0/21', '213.219.32.0/19', '23.239.0.0/16', '23.92.16.0/20']
            },
            'vultr': {
            'headers': ['vultr', 'x-vultr-id', 'x-vultr-pop', 'server: vultr'],
            'ips': ['45.76.0.0/16', '45.32.0.0/16', '63.209.32.0/19', '104.156.224.0/19', '108.61.0.0/16', '140.82.0.0/16', '144.202.0.0/16', '149.28.0.0/16', '155.138.128.0/17', '199.247.0.0/16', '207.246.64.0/18', '95.179.128.0/17', '217.163.16.0/20']
            },
            'hetzner': {
            'headers': ['hetzner', 'x-hetzner', 'x-hetzner-request-id', 'hetzner-cloud'],
            'ips': ['5.9.0.0/16', '78.46.0.0/15', '88.198.0.0/16', '94.130.0.0/15', '116.203.0.0/16', '135.181.0.0/16', '136.243.0.0/16', '138.201.0.0/16', '144.76.0.0/16', '148.251.0.0/16', '159.69.0.0/16', '162.55.0.0/16', '167.233.0.0/16', '168.119.0.0/16', '176.9.0.0/16', '178.63.0.0/16', '195.201.0.0/16', '213.133.96.0/19', '213.239.192.0/18', '23.88.0.0/16', '49.12.0.0/16', '65.108.0.0/16', '85.10.192.0/18', '95.216.0.0/16']
            },
            'ovh': {
            'headers': ['ovh', 'x-ovh-id', 'x-ovh-request-id', 'ovh-cache'],
            'ips': ['51.38.0.0/16', '51.68.0.0/16', '51.75.0.0/16', '51.77.0.0/16', '51.79.0.0/16', '51.81.0.0/16', '51.83.0.0/16', '51.89.0.0/16', '51.91.0.0/16', '54.36.0.0/16', '54.37.0.0/16', '137.74.0.0/16', '141.94.0.0/16', '141.95.0.0/16', '142.44.128.0/17', '146.59.0.0/16', '147.135.0.0/16', '149.202.0.0/16', '151.80.0.0/16', '152.228.128.0/17', '158.69.0.0/16', '164.132.0.0/16', '167.114.0.0/16', '176.31.0.0/16', '178.32.0.0/15', '188.165.0.0/16', '192.95.0.0/16', '193.70.0.0/17', '198.27.64.0/18', '198.50.128.0/17', '213.186.0.0/16', '213.251.128.0/18', '37.187.0.0/16', '37.59.0.0/16', '5.135.0.0/16', '5.196.0.0/16', '5.39.0.0/16', '87.98.128.0/17', '91.121.0.0/16', '92.222.0.0/16', '94.23.0.0/16']
            },
            'scaleway': {
            'headers': ['scaleway', 'x-scaleway-id', 'x-scaleway-request-id', 'x-scw-request-id'],
            'ips': ['51.15.0.0/16', '51.158.0.0/15', '62.210.0.0/16', '163.172.0.0/16', '195.154.0.0/16', '212.47.224.0/19', '212.83.128.0/19']
            },
            'check_point': {
            'headers': ['check point', 'cpx-cache-status', 'x-checkpoint', 'x-fw-request-id'],
            'ips': []  # Custom deployments
        #  
        
            },
            'cisco_waf': {
            'headers': ['cisco', 'x-cisco-request-asset', 'x-cisco-waf', 'cisco-waf'],
            'ips': []  # Custom deployments
            },
            'juniper_waf': {
            'headers': ['juniper', 'x-juniper-id', 'x-juniper-waf', 'junos-waf'],
            'ips': []  # Custom deployments
            },
            'sonicwall': {
            'headers': ['sonicwall', 'x-sonicwall-id', 'x-sonicwall-waf', 'sonicwall-waf'],
            'ips': []  # Custom deployments
            },
            'watchguard': {
            'headers': ['watchguard', 'x-watchguard', 'x-wg-request-id', 'watchguard-waf'],
            'ips': []  # Custom deployments
            },
            'sophos_waf': {
            'headers': ['sophos', 'x-sophos-id', 'x-sophos-waf', 'sophos-firewall'],
            'ips': []  # Custom deployments
            },
            'radware_waf': {
            'headers': ['radware', 'x-radware-waf', 'radware-waf', 'x-radware-request-id'],
            'ips': []  # Custom deployments
        #
        
            },
            'a10_networks': {
            'headers': ['a10', 'x-a10-request-id', 'a10-waf', 'x-a10-thunder'],
            'ips': []  # Custom deployments
            },
            'array_networks': {
            'headers': ['array', 'x-array-id', 'array-waf', 'x-array-networks'],
            'ips': []  # Custom deployments
            },
            'kemp_waf': {
            'headers': ['kemp', 'x-kemp-loadmaster', 'kemp-waf', 'x-kemp-request'],
            'ips': []  # Custom deployments
            },
            'apache_waf': {
            'headers': ['apache', 'x-apache', 'server: apache', 'x-apache-waf'],
            'ips': []  # Custom deployments
        # 
        
            },
            'microsoft_iis': {
            'headers': ['microsoft-iis', 'x-aspnet-version', 'x-powered-by', 'server: microsoft-iis'],
            'ips': []  # Custom deployments
            },
            'tomcat_waf': {
            'headers': ['tomcat', 'x-tomcat-id', 'server: apache-coyote', 'x-tomcat-waf'],
            'ips': []  # Custom deployments
            },
            'jetty_waf': {
            'headers': ['jetty', 'x-jetty', 'server: jetty', 'x-jetty-waf'],
            'ips': []  # Custom deployments
            },
            'weblogic_waf': {
            'headers': ['weblogic', 'x-weblogic-request-clusterinfo', 'x-weblogic-waf', 'server: weblogic'],
            'ips': []  # Custom deployments
            },
            'websphere_waf': {
            'headers': ['websphere', 'x-websphere-id', 'x-websphere-waf', 'server: websphere'],
            'ips': []  # Custom deployments
            },
            'jboss_waf': {
            'headers': ['jboss', 'x-jboss', 'server: jboss-web', 'x-jboss-waf'],
            'ips': []  # Custom deployments
            },
            'wildfly_waf': {
            'headers': ['wildfly', 'x-wildfly', 'server: wildfly', 'x-wildfly-waf'],
            'ips': []  # Custom deployments
            },
            'glassfish_waf': {
            'headers': ['glassfish', 'x-glassfish-id', 'server: glassfish', 'x-glassfish-waf'],
            'ips': []  # Custom deployments
            },
            'resin_waf': {
            'headers': ['resin', 'x-resin-id', 'server: resin', 'x-resin-waf'],
            'ips': []  # Custom deployments
            },
            'undertow_waf': {
            'headers': ['undertow', 'x-undertow', 'server: undertow', 'x-undertow-waf'],
            'ips': []  # Custom deployments 
            },
            'signal_sciences': {
            'headers': ['signal sciences', 'sigsci-waf', 'x-sigsci-requestid', 'x-sigsci-agentresponse'],
            'ips': ['52.4.0.0/16', '52.5.0.0/16', '52.7.0.0/16', '54.85.0.0/16', '54.88.0.0/16', '107.23.0.0/17']
            
        # 
        
            },
            'fastly_signal_sciences': {
            'headers': ['fastly', 'sigsci', 'x-sigsci-tags', 'x-fastly-sigsci'],
            'ips': ['23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24']  # Same as Fastly
            },
            'threatx_waf': {
            'headers': ['threatx', 'x-threatx-id', 'x-threatx-score', 'threatx-waf'],
            'ips': ['54.208.0.0/16', '54.209.0.0/16', '107.22.0.0/16', '174.129.0.0/16']
            },
            'wallarm_waf': {
            'headers': ['wallarm', 'x-wallarm-mode', 'wallarm-status', 'x-wallarm-request-id'],
            'ips': ['34.102.136.180/32', '35.235.66.155/32', '104.199.0.0/16', '35.184.0.0/16'] 
            },
            'apptrana_waf': {
            'headers': ['apptrana', 'indusface', 'x-apptrana', 'x-indusface-waf'],
            'ips': ['52.66.0.0/16', '13.127.0.0/16', '13.234.0.0/15', '35.154.0.0/16'] 
            },
            'qualys_waf': {
            'headers': ['qualys', 'x-qualys-scan', 'qualys-waf', 'x-qualys-request'],
            'ips': ['64.39.96.0/20', '199.7.52.0/24', '216.245.194.0/24', '216.245.195.0/24']
        # 
        
            },
            'rapid7_waf': {
            'headers': ['rapid7', 'x-r7-id', 'rapid7-waf', 'x-rapid7-scan'],
            'ips': ['208.118.227.0/24', '208.118.228.0/24', '5.153.225.0/24', '71.6.233.0/24']
            },
            'veracode_waf': {
            'headers': ['veracode', 'x-veracode', 'veracode-waf', 'x-veracode-scan'],
            'ips': ['208.70.144.0/24', '96.31.172.0/24', '204.154.64.0/22']  
            },
            'whitehat_waf': {
            'headers': ['whitehat security', 'x-whitehat', 'whitehat-waf', 'x-whitehat-scan'],
            'ips': ['206.51.29.0/24', '208.118.240.0/24', '69.46.86.0/24']
            },
            'checkmarx_waf': {
            'headers': ['checkmarx', 'x-checkmarx', 'checkmarx-waf', 'x-checkmarx-scan'],
            'ips': []  # Cloud-based service with dynamic IPs 
            },
            'synopsys_waf': {
            'headers': ['synopsys', 'x-synopsys', 'synopsys-waf', 'x-synopsys-scan'],
            'ips': []  # Cloud-based service with dynamic IPs
            },
            'hcl_appscan': {
            'headers': ['appscan', 'x-hcl-appscan', 'hcl-waf', 'x-appscan-request'],
            'ips': []  # Cloud-based service with dynamic IPs
            },
            'micro_focus_waf': {
            'headers': ['micro focus', 'x-microfocus', 'microfocus-waf', 'x-fortify'],
            'ips': []  # Cloud-based service with dynamic IPs 
            },
            'sonarqube_waf': {
            'headers': ['sonar', 'x-sonar', 'sonarqube-waf', 'x-sonarqube'],
            'ips': []  # Self-hosted typically
            },
            'snyk_waf': {
            'headers': ['snyk', 'x-snyk-id', 'snyk-waf', 'x-snyk-scan'],
            'ips': []  # Cloud-based service with dynamic IPs
            },
            'naxsi_waf': {
            'headers': ['naxsi', 'x-naxsi-sig', 'naxsi-waf', 'x-naxsi-evid'],
            'ips': []  # Nginx module, custom deployments
        # 
        
            },
            'lua_resty_waf': {
            'headers': ['lua-resty-waf', 'x-lua-resty', 'lua-waf', 'x-lua-waf'],
            'ips': []  # OpenResty module, custom deployments
            },
            'openappsec_waf': {
            'headers': ['openappsec', 'x-openappsec', 'openappsec-waf', 'x-openappsec-id'],
            'ips': []  # Open source solution, custom deployments  
            },
            'shadow_daemon': {
            'headers': ['shadowd', 'x-shadow-daemon', 'shadow-daemon-waf', 'x-shadowd'],
            'ips': []  # Open source solution, custom deployments
            },
            'azure_front_door': {
            'headers': ['azurefd', 'x-azure-fdid', 'x-fd-healthprobe', 'x-azure-ref'],
            'ips': ['40.90.0.0/16', '40.126.0.0/18', '13.73.248.16/29', '20.21.37.40/29', '20.36.120.104/29', '20.37.156.216/29', '20.37.195.96/29', '20.38.85.152/29', '20.39.13.32/29', '20.41.6.0/28', '20.42.4.208/29', '20.42.129.152/29', '20.42.224.40/29', '20.43.41.136/29', '20.43.65.128/29', '20.43.130.80/29', '20.44.4.72/29', '20.44.17.80/29', '20.45.113.128/29', '20.45.192.104/29', '20.46.13.32/29', '20.150.160.0/23', '20.189.107.0/24', '40.67.48.0/21', '40.67.56.0/24', '40.67.60.0/22', '40.82.248.0/22', '40.90.23.192/26', '40.90.24.0/25', '40.90.25.0/26', '40.90.26.64/26', '40.90.27.0/25', '40.90.28.0/24', '40.90.30.0/24', '40.90.31.0/25', '40.90.128.0/17', '40.119.8.0/25', '40.119.64.0/22']
        # 
        
            },
            'google_cloud_cdn': {
            'headers': ['x-goog-meta', 'x-guploader-uploadid', 'x-goog-generation', 'x-google-cache-control'],
            'ips': ['8.0.0.0/8', '34.0.0.0/8', '35.0.0.0/8', '104.0.0.0/8', '107.178.0.0/15', '108.170.0.0/15', '108.177.0.0/15', '130.211.0.0/16', '142.250.0.0/15', '146.148.0.0/16', '162.216.0.0/15', '162.222.0.0/15', '172.217.0.0/15', '172.253.0.0/15', '173.194.0.0/15', '192.158.0.0/15', '199.192.0.0/14', '199.223.0.0/15', '209.85.0.0/15']  # Same as Google Cloud Armor 
       
            },   
            'ironbee': {
            'headers': ['ironbee', 'x-ironbee'],
            'ips': []  # Open source WAF, custom deployments
            },
            'webknight': {
            'headers': ['webknight', 'aqtronix webknight'],
            'ips': []  # ISAPI filter, no specific IP ranges
            },
            'dotdefender': {
            'headers': ['dotdefender', 'applicure'],
            'ips': []  # Software WAF, custom deployments 
            },
            'comodo': {
            'headers': ['comodo', 'x-comodo-waf'],
            'ips': ['5.188.0.0/16', '5.189.0.0/16', '5.254.0.0/16', '8.39.0.0/16', '45.86.0.0/16', '64.94.0.0/16', '91.200.0.0/16', '185.162.0.0/16', '192.145.0.0/16']
            },
            'wordfence': {
            'headers': ['wordfence', 'x-wordfence-blocked'],
            'ips': []  # Plugin-based, no specific IP ranges
        # 
        
            },
            'malcare': {
            'headers': ['malcare', 'x-malcare'],
            'ips': ['35.200.0.0/16', '35.244.0.0/16']  # Google Cloud IPs 
            },
            'ithemes_security': {
            'headers': ['ithemes', 'x-ithemes'],
            'ips': []  # Plugin-based
            },
            'ninjafirewall': {
            'headers': ['ninjafirewall', 'x-ninja-firewall'],
            'ips': []  # Plugin-based
            },
            'bulletproof_security': {
            'headers': ['bulletproof', 'x-bps'],
            'ips': []  # Plugin-based
            },
            'cloudways': {
            'headers': ['cloudways', 'x-cloudways'],
            'ips': ['35.185.0.0/16', '35.196.0.0/16', '35.237.0.0/16', '104.196.0.0/16', '146.148.0.0/16']
        #
        
            },
            'kinsta': {
            'headers': ['kinsta', 'x-kinsta-cache'],
            'ips': ['35.196.0.0/16', '104.196.0.0/16', '130.211.0.0/16', '146.148.0.0/16']    
            },
            'wp_engine': {
            'headers': ['wpengine', 'x-wpengine'],
            'ips': ['35.196.0.0/16', '104.196.0.0/16', '162.222.0.0/16', '192.0.96.0/20']
            },
            'flywheel': {
            'headers': ['flywheel', 'x-flywheel'],
            'ips': ['35.185.0.0/16', '104.198.0.0/16', '146.148.0.0/16']
            },
            'pressable': {
            'headers': ['pressable', 'x-pressable'],
            'ips': ['104.196.0.0/16', '146.148.0.0/16']  
            },
            'godaddy': {
            'headers': ['godaddy', 'x-godaddy'],
            'ips': ['31.222.116.0/24', '50.63.202.0/24', '97.74.0.0/16', '173.201.0.0/16', '184.168.0.0/16', '198.71.0.0/16', '208.109.0.0/16']
                
        
            },
            'namecheap': {
            'headers': ['namecheap', 'x-namecheap'],
            'ips': ['198.54.0.0/16', '199.101.0.0/16', '216.172.0.0/16']      
            },
            'bluehost': {
            'headers': ['bluehost', 'x-bluehost'],
            'ips': ['50.87.0.0/16', '66.147.0.0/16', '68.178.0.0/16', '74.220.0.0/16', '162.144.0.0/16', '166.62.0.0/16']
            },
            'hostgator': {
            'headers': ['hostgator', 'x-hostgator'],
            'ips': ['50.87.0.0/16', '68.178.0.0/16', '74.220.0.0/16', '162.144.0.0/16', '166.62.0.0/16']
            },
            'siteground': {
            'headers': ['siteground', 'x-siteground'],
            'ips': ['35.214.0.0/16', '35.241.0.0/16', '107.180.0.0/16', '162.159.0.0/16', '172.105.0.0/16']
            },
            'dreamhost': {
            'headers': ['dreamhost', 'x-dreamhost'],
            'ips': ['66.33.0.0/16', '75.119.0.0/16', '173.236.0.0/16', '208.113.0.0/16']
            },
            'a2_hosting': {
            'headers': ['a2hosting', 'x-a2-optimized'],
            'ips': ['72.52.0.0/16', '96.126.0.0/16', '108.171.0.0/16', '162.216.0.0/16', '198.252.0.0/16']
            },
            'inmotion': {
            'headers': ['inmotionhosting', 'x-inmotion'],
            'ips': ['65.61.0.0/16', '70.39.0.0/16', '74.124.0.0/16', '162.144.0.0/16', '173.236.0.0/16']
            },
            'liquid_web': {
            'headers': ['liquidweb', 'x-liquidweb'],
            'ips': ['69.167.0.0/16', '72.55.0.0/16', '209.40.0.0/16']
            },
            'media_temple': {
            'headers': ['mediatemple', 'x-mt-id'],
            'ips': ['64.207.0.0/16', '66.228.0.0/16', '72.47.0.0/16', '216.120.0.0/16']
            },
            'traefik': {
            'headers': ['traefik', 'x-traefik'],
            'ips': []  # Custom deployments
        
        
            },
            'envoy': {
            'headers': ['envoy', 'x-envoy', 'x-request-id'],
            'ips': []  # Custom deployments  
            },
            'sucuri': {
            'headers': ['sucuri', 'x-sucuri-id', 'cloudproxy', 'x-sucuri-cache'],
            'ips': ['192.88.134.0/23', '185.93.228.0/22', '192.169.0.0/16', '198.58.0.0/16', '198.100.0.0/16', '199.167.0.0/16']
        
        
            },
            'sitelock': {
            'headers': ['sitelock', 'x-sitelock-id'],
            'ips': ['69.58.0.0/16', '74.124.0.0/16', '198.58.0.0/16']
            },          
            'squid': {
            'headers': ['squid', 'x-squid-error', 'via'],
            'ips': []  # Custom deployments
            },
            'varnish': {
            'headers': ['varnish', 'x-varnish', 'x-cache'],
            'ips': []  # Custom deployments
            },
            'litespeed': {
            'headers': ['litespeed', 'x-litespeed-cache'],
            'ips': []  # Custom deployments 
            },
            'openlitespeed': {
            'headers': ['openlitespeed', 'x-ols'],
            'ips': []  # Custom deployments
            },
            'cherokee': {
            'headers': ['cherokee', 'x-cherokee'],
            'ips': []  # Custom deployments
            },
            'lighttpd': {
            'headers': ['lighttpd', 'x-lighttpd'],
            'ips': []  # Custom deployments
            },
            'caddy': {
            'headers': ['caddy', 'x-caddy'],
            'ips': []  # Custom deployments
            },
            'kong': {
            'headers': ['kong', 'x-kong-upstream-latency'],
            'ips': []  # Custom deployments
         # 
        
            },
            'ambassador': {
            'headers': ['ambassador', 'x-ambassador'],
            'ips': []  # Custom deployments
            },
            'istio': {
            'headers': ['istio', 'x-envoy-upstream-service-time'],
            'ips': []  # Custom deployments
            },
            'linkerd': {
            'headers': ['linkerd', 'l5d'],
            'ips': []  # Custom deployments
            },
            'consul_connect': {
            'headers': ['consul', 'x-consul'],
            'ips': []  # Custom deployments
            },
            'zuul': {
            'headers': ['zuul', 'x-zuul'],
            'ips': []  # Custom deployments
            },
            'spring_gateway': {
            'headers': ['spring-cloud-gateway', 'x-gateway'],
            'ips': []  # Custom deployments
            },
            'express_gateway': {
            'headers': ['express-gateway', 'x-express'],
            'ips': []  # Custom deployments
            },
            'krakend': {
            'headers': ['krakend', 'x-krakend'],
            'ips': []  # Custom deployments
            },
            'tyk': {
            'headers': ['tyk', 'x-tyk'],
            'ips': []  # Custom deployments
            },
            'wso2': {
            'headers': ['wso2', 'x-wso2'],
            'ips': []  # Custom deployments
            },
            'mulesoft': {
            'headers': ['mulesoft', 'x-mule'],
            'ips': []  # Custom deployments
            },
            'apigee': {
            'headers': ['apigee', 'x-apigee'],
            'ips': ['23.236.48.0/20', '23.251.144.0/20', '35.184.0.0/13', '35.192.0.0/12', '107.178.192.0/18']
            },
            'kubernetes_ingress': {
            'headers': ['kubernetes', 'x-k8s'],
            'ips': []  # Custom deployments
        # 
        
            },
            'nginx_ingress': {
            'headers': ['ingress-nginx', 'x-ingress-controller'],
            'ips': []  # Custom deployments
            },
            'traefik_ingress': {
            'headers': ['traefik', 'x-forwarded-proto'],
            'ips': []  # Custom deployments 
            },
            'haproxy_ingress': {
            'headers': ['haproxy-ingress', 'x-haproxy'],
            'ips': []  # Custom deployments 
            },
            'istio_gateway': {
            'headers': ['istio-proxy', 'x-istio'],
            'ips': []  # Custom deployments
            },
            'ambassador_edge': {
            'headers': ['ambassador', 'x-ambassador-auth'],
            'ips': []  # Custom deployments
            },
            'gloo_edge': {
            'headers': ['gloo', 'x-gloo'],
            'ips': []  # Custom deployments
            },
            'contour': {
            'headers': ['contour', 'x-contour'],
            'ips': []  # Custom deployments
            },
            'kong_kubernetes': {
            'headers': ['kong-ingress', 'x-kong'],
            'ips': []  # Custom deployments
            },
            'lambda_edge': {
            'headers': ['lambda@edge', 'x-amz-executed-version'],
            'ips': []  # Uses AWS IP ranges
        # 
        
            },
            'azure_functions': {
            'headers': ['azure-functions', 'x-azure-functions'],
            'ips': ['20.0.0.0/8', '40.0.0.0/8', '52.0.0.0/8']  # Azure IP ranges 
            },
            'cloud_functions': {
            'headers': ['google-cloud-functions', 'x-cloud-trace'],
            'ips': ['8.0.0.0/8', '34.0.0.0/8', '35.0.0.0/8']  # Google Cloud IP ranges
            },
            'cloudflare_workers': {
            'headers': ['cloudflare-workers', 'cf-worker'],
            'ips': ['104.16.0.0/12', '172.64.0.0/13', '173.245.48.0/20']  # Cloudflare IPs
            },
            'fastly_compute': {
            'headers': ['fastly-compute', 'x-compute'],
            'ips': ['23.235.32.0/20', '146.75.0.0/16', '151.101.0.0/16']  # Fastly IPs
            },
            'vercel': {
            'headers': ['vercel', 'x-vercel'],
            'ips': ['76.76.21.0/24', '192.241.128.0/17', '199.27.72.0/21']
            },
            'netlify': {
            'headers': ['netlify', 'x-nf-request-id'],
            'ips': ['54.152.0.0/16', '54.156.0.0/16', '54.224.0.0/15']
            },
            'deno_deploy': {
            'headers': ['deno', 'x-deno-deploy'],
            'ips': ['143.42.0.0/16', '143.198.0.0/16']
            },
            'panther': {
            'headers': ['panther', 'x-panther'],
            'ips': []  # Cloud-based, uses provider IPs
        # 
        
            },
            'lacework': {
            'headers': ['lacework', 'x-lacework'],
            'ips': ['35.80.0.0/16', '52.32.0.0/16', '54.70.0.0/16']
            },
            'aqua_security': {
            'headers': ['aqua', 'x-aqua'],
            'ips': []  # Cloud-based
            },
            'twistlock': {
            'headers': ['twistlock', 'x-twistlock'],
            'ips': []  #  part of Prisma Cloud
            },
            'prisma_cloud': {
            'headers': ['prisma', 'x-prisma'],
            'ips': ['35.80.0.0/16', '52.32.0.0/16', '54.70.0.0/16']  # Palo Alto Networks IPs
            },
            'sysdig': {
            'headers': ['sysdig', 'x-sysdig'],
            'ips': []  # Cloud-based
            },
            'falco': {
            'headers': ['falco', 'x-falco'],
            'ips': []  # Open source, custom deployments
            },
            'neuvector': {
            'headers': ['neuvector', 'x-neuvector'],
            'ips': []  # Cloud-based 
            },
            'trend_micro': {
            'headers': ['trendmicro', 'x-trend'],
            'ips': ['150.70.0.0/16', '203.10.0.0/16', '210.150.0.0/16'] 
            },
            'datadome': {
            'headers': ['datadome', 'x-datadome', 'dd_'],
            'ips': ['35.180.0.0/16', '52.47.0.0/16', '54.93.0.0/16']
        # 
        
            },
            'reblaze': {
            'headers': ['reblaze', 'x-reblaze'],
            'ips': ['45.134.140.0/22', '185.229.0.0/22', '199.182.0.0/22']
            },
            'perimeterx': {
            'headers': ['perimeterx', '_px', 'x-px'],
            'ips': ['52.28.0.0/16', '52.57.0.0/16', '52.208.0.0/16'] 
            },
            'shape_security': {
            'headers': ['shape', 'x-shape'],
            'ips': []  # 
            },         
            'human_security': {
            'headers': ['humansecurity', 'x-human'],
            'ips': ['35.201.0.0/16', '104.199.0.0/16', '146.148.0.0/16']  # Google Cloud IPs
            },
            'human': {
            'headers': ['human', 'x-human-sec'],
            'ips': ['35.201.0.0/16', '104.199.0.0/16', '146.148.0.0/16']  # Same as HUMAN Security 
            },
            'arkose_labs': {
            'headers': ['arkose', 'x-arkose'],
            'ips': ['13.52.0.0/16', '54.67.0.0/16', '104.196.0.0/16']  # AWS IP ranges  
            },
            'castle': {
            'headers': ['castle', 'x-castle'],
            'ips': ['52.52.0.0/16', '54.67.0.0/16', '104.196.0.0/16']  # AWS IP ranges   
            },
            'biocatch': {
            'headers': ['biocatch', 'x-biocatch'],
            'ips': ['52.21.0.0/16', '52.45.0.0/16', '54.84.0.0/16']  # AWS IP ranges 
            },
            'threatmetrix': {
            'headers': ['threatmetrix', 'x-tm'],
            'ips': ['52.32.0.0/16', '52.36.0.0/16', '54.148.0.0/16']  # AWS IP ranges (LexisNexis)
            },
            'kount': {
            'headers': ['kount', 'x-kount'],
            'ips': ['52.36.0.0/16', '52.43.0.0/16', '54.70.0.0/16']  # AWS IP ranges
            },
            'riskified': {
            'headers': ['riskified', 'x-riskified'],
            'ips': ['52.200.0.0/16', '52.205.0.0/16', '54.88.0.0/16']  # AWS IP ranges
        # 
        
            },
            'signifyd': {
            'headers': ['signifyd', 'x-signifyd'],
            'ips': ['52.33.0.0/16', '52.43.0.0/16', '54.70.0.0/16']  # AWS IP ranges  
            },
            'sift': {
            'headers': ['sift', 'x-sift'],
            'ips': ['52.32.0.0/16', '52.36.0.0/16', '54.148.0.0/16']  # AWS IP ranges  
            },
            'forter': {
            'headers': ['forter', 'x-forter'],
            'ips': ['52.48.0.0/16', '52.64.0.0/16', '54.66.0.0/16']  # AWS IP ranges
            },
            'clearsale': {
            'headers': ['clearsale', 'x-clearsale'],
            'ips': ['52.67.0.0/16', '54.94.0.0/16', '177.71.0.0/16']  # AWS + Brazil IPs 
            },
            'maxmind': {
            'headers': ['maxmind', 'x-maxmind'],
            'ips': ['162.158.0.0/15', '172.69.0.0/16', '108.162.0.0/16']  # Cloudflare IPs
        # 
        
            },
            'ipqualityscore': {
            'headers': ['ipqualityscore', 'x-ipqs'],
            'ips': ['104.156.0.0/16', '104.238.0.0/16', '107.191.0.0/16']  # Various hosting IPs
            },
            'minfraud': {
            'headers': ['minfraud', 'x-minfraud'],
            'ips': ['162.158.0.0/15', '172.69.0.0/16']  # MaxMind/Cloudflare IPs
            },
            'fraudlabs': {
            'headers': ['fraudlabs', 'x-fraudlabs'],
            'ips': ['104.200.0.0/16', '192.241.0.0/16', '198.199.0.0/16']  # Various hosting IPs
            },
            'shield': {
            'headers': ['shield', 'x-shield'],
            'ips': ['52.76.0.0/16', '54.169.0.0/16', '54.255.0.0/16']  # AWS Singapore IPs
            },
            'cybersource': {
            'headers': ['cybersource', 'x-cybersource'],
            'ips': ['52.32.0.0/16', '52.36.0.0/16', '54.148.0.0/16']  # Visa AWS IPs
        # 
        
            },
            'adyen': {
            'headers': ['adyen', 'x-adyen'],
            'ips': ['52.50.0.0/16', '52.57.0.0/16', '54.93.0.0/16']  # AWS EU IPs
            },
            'stripe_radar': {
            'headers': ['stripe', 'x-stripe-radar'],
            'ips': ['52.32.0.0/16', '52.36.0.0/16', '54.148.0.0/16']  # Stripe AWS IPs 
            },
            'paypal': {
            'headers': ['paypal', 'x-pp-silover'],
            'ips': ['64.4.0.0/16', '66.211.0.0/16', '173.0.0.0/16']  # PayPal IP ranges
            },
            'afterpay': {
            'headers': ['afterpay', 'x-afterpay'],
            'ips': ['52.62.0.0/16', '54.66.0.0/16', '54.79.0.0/16']  # AWS Australia IPs   
            },
            'affirm': {
            'headers': ['affirm', 'x-affirm'],
            'ips': ['52.32.0.0/16', '52.36.0.0/16', '54.148.0.0/16']  # AWS IP ranges  
            },
            'sezzle': {
            'headers': ['sezzle', 'x-sezzle'],
            'ips': ['52.15.0.0/16', '52.52.0.0/16', '54.67.0.0/16']  # AWS IP ranges
            },
            'zip': {
            'headers': ['zip', 'x-zip-pay'],
            'ips': ['52.63.0.0/16', '54.66.0.0/16', '54.79.0.0/16']  # AWS Australia IPs
        
            }
        }    
                      
            
        

    async def detect_firewall(self, domain):
        """Detect firewall"""
        print(f"{Colors.GREEN}[*] Scanning for firewall protection...{Colors.END}")
        
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Colors.GREEN}[*] Target IP: {ip}{Colors.END}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{domain}", timeout=10, ssl=False) as response:
                    headers = str(response.headers).lower()
                    
                    for fw_name, patterns in self.firewall_patterns.items():
                        for header in patterns['headers']:
                            if header in headers:
                                print(f"{Colors.GREEN}[!] Firewall Detected: {Colors.CYAN}{fw_name.lower()}{Colors.END}")
                                return fw_name, 95
            
            print(f"{Colors.GREEN}[+] No major firewall detected{Colors.END}")
            return None, 0
            
        except Exception as e:
            print(f"{Colors.RED}[!] Firewall detection error: {e}{Colors.END}")
            return None, 0


#subdomains depend on nature of the site 

class PowerfulBruteforce:
    def __init__(self):
        self.subdomain_wordlist = self.generate_wordlist()
    
    def generate_wordlist(self):
        """Generate subdomain wordlist with weak protection targets"""
        words = [
            'api', 'admin', 'cpanel', 'backend', 'origin', 'direct',
            'dev', 'staging', 'test', 'cdn', 'assets', 'static',
            'app', 'mobile', 'mail', 'ftp', 'webmail', 'blog',
            'development', 'develop', 'alpha', 'beta', 'demo', 'sandbox',
            'preprod', 'pre-prod', 'preproduction', 'uat', 'qa', 'quality',
            'experimental', 'pilot', 'prototype',
            'testapi', 'stagingapi', 'devapi', 'adminapi', 'internalapi',
            'privateapi', 'secureapi', 'authapi', 'oauth', 'sso',
            'old', 'legacy', 'classic', 'v1', 'v2', 'v3', 'version1',
            'previous', 'archive', 'backup', 'temp', 'tmp',
            'local', 'localhost', 'internal', 'intranet', 'vpn', 'remote',
            'regional', 'europe', 'asia', 'us', 'uk', 'eu', 'na',
            'manage', 'manager', 'management', 'control', 'controller',
            'dashboard', 'portal', 'gateway', 'proxy', 'router',
            'monitor', 'monitoring', 'analytics', 'stats', 'statistics',
            'metric', 'metrics', 'status', 'health', 'ping',
            'db', 'database', 'sql', 'mysql', 'postgres', 'mongo',
            'storage', 'store', 'data', 'files', 'uploads',
            'security', 'secure', 'auth', 'authentication', 'login',
            'signin', 'oauth2', 'saml', 'jwt', 'token',
            'server', 'servers', 'cluster', 'kubernetes', 'k8s',
            'docker', 'vm', 'virtual', 'cloud', 'aws', 'azure',
            'alternate', 'alt', 'secondary', 'shadow', 'mirror',
            'replica', 'clone', 'copy', 'duplicate',
            'root', 'super', 'superuser', 'master', 'primary',
            'main', 'core', 'central', 'global', 'world'
            'phpmyadmin', 'adminer', 'webmin', 'plesk', 'directadmin',
            'whm', 'cpanel', 'webmail', 'roundcube', 'squirrelmail',
            'noc', 'operations', 'tech', 'technical', 'support',
            'helpdesk', 'it', 'infrastructure', 'network',
            'git', 'svn', 'jenkins', 'jenkinsci', 'teamcity',
            'bamboo', 'nexus', 'artifactory', 'sonarqube',
            'publicapi', 'openapi', 'restapi', 'graphql', 'grpc',
            'websocket', 'socket', 'ws', 'wss',
            'kibana', 'grafana', 'prometheus', 'elasticsearch',
            'redis', 'memcached', 'rabbitmq', 'kafka',
            'hidden', 'secret', 'private', 'confidential',
            'restricted', 'securearea', 'adminarea'
        ]
        return words



class EvilWAFBypass:
    def __init__(self):
        self.session = None
        self.user_agents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36']
        self.detector = FirewallDetector()
        self.bruteforce = PowerfulBruteforce()

    async def init_session(self):
        """Initialize session"""
        timeout = aiohttp.ClientTimeout(total=20)
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)

    async def close_session(self):
        if self.session:
            await self.session.close()

    def get_random_ua(self):
        return random.choice(self.user_agents)

    # 
    
    
    async def smart_subdomain_validation(self, domain):
        """Smart subdomain discovery"""
        print(f"{Colors.GREEN}[+] PHASE 1: Smart Subdomain Discovery{Colors.END}")
        
        valid_subs = []
        
        for sub in self.bruteforce.subdomain_wordlist:
            subdomain = f"{sub}.{domain}"
            
            try:
                socket.setdefaulttimeout(3)
                ip = socket.gethostbyname(subdomain)
                valid_subs.append(subdomain)
                print(f"{Colors.WHITE}[-] {subdomain:<40} {Colors.GREEN}DNS found{Colors.END}")
                
            except socket.gaierror:
                print(f"{Colors.WHITE}[-] {subdomain:<40} {Colors.BLUE}No DNS record{Colors.END}")
                continue
            except Exception:
                print(f"{Colors.WHITE}[-] {subdomain:<40} {Colors.RED}DNS error{Colors.END}")
                continue
        
        print(f"{Colors.GREEN}[+] Found {len(valid_subs)} valid subdomains{Colors.END}")
        return valid_subs

    async def test_valid_subdomains(self, domain, valid_subdomains):
        """Test subdomains with improved logic"""
        if not valid_subdomains:
            print(f"{Colors.RED}[-] No valid subdomains to test{Colors.END}")
            return []
        
        print(f"{Colors.GREEN}[+] Testing {len(valid_subdomains)} valid subdomains...{Colors.END}")
        working_subs = []
        
        for subdomain in valid_subdomains:
            # Try both HTTP and HTTPS
            if await self.improved_subdomain_test(subdomain, domain):
                working_subs.append(subdomain)
                print(f"{Colors.WHITE}[-] {subdomain:<40} {Colors.GREEN}Bypass Success{Colors.END}")
            else:
                print(f"{Colors.WHITE}[-] {subdomain:<40} {Colors.RED}Bypass failed{Colors.END}")
            
            await asyncio.sleep(0.2)
        
        return working_subs

    async def improved_subdomain_test(self, subdomain, main_domain):
        """Subdomain test with multiple attempts"""
        try:
            headers = {'User-Agent': self.get_random_ua()}
            
            # Try HTTPS first
            async with self.session.get(f"https://{subdomain}", headers=headers, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    return True
            
            # Try HTTP if HTTPS fails
            async with self.session.get(f"http://{subdomain}", headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    return True
            
            return False
            
        except Exception:
            return False

    # 
    
    async def dns_history_bypass(self, domain):
        """DNS history bypass"""
        print(f"{Colors.GREEN}[+] PHASE 2: DNS History Bypass{Colors.END}")
        
        working_ips = []
        
        try:
            current_ip = socket.gethostbyname(domain)
            ip_variants = self.generate_ip_variants(current_ip)
            
            print(f"{Colors.WHITE}[*] Testing {len(ip_variants)} IP variants{Colors.END}")
            
            for ip in ip_variants:
                if await self.improved_ip_test(domain, ip):
                    working_ips.append(ip)
                    print(f"{Colors.WHITE}[-] {ip:<40} {Colors.GREEN}Bypass Success{Colors.END}")
                else:
                    print(f"{Colors.WHITE}[-] {ip:<40} {Colors.RED}Bypass Failed{Colors.END}")
                
                await asyncio.sleep(0.2)
        
        except Exception as e:
            print(f"{Colors.RED}[-] DNS bypass error: {e}{Colors.END}")
        
        return working_ips

    def generate_ip_variants(self, ip):
        """Generate IP variants"""
        variants = [ip]
        parts = ip.split('.')
        
        if len(parts) == 4:
            # More  IP variants firewalls especially cloudflare
            variants.extend([
                f"{parts[0]}.{parts[1]}.{parts[2]}.1",
                f"{parts[0]}.{parts[1]}.{parts[2]}.2",
                f"{parts[0]}.{parts[1]}.{parts[2]}.10",
                f"{parts[0]}.{parts[1]}.{parts[2]}.50",
                f"{parts[0]}.{parts[1]}.{parts[2]}.100",
                f"{parts[0]}.{parts[1]}.{parts[2]}.200",
                f"{parts[0]}.{parts[1]}.{parts[2]}.254",
                f"{parts[0]}.{parts[1]}.{parts[2]}.255",
                f"{parts[0]}.{parts[1]}.{parts[2]}.101",
                f"{parts[0]}.{parts[1]}.{parts[2]}.102",
                f"{parts[0]}.{parts[1]}.{parts[2]}.103",
                f"{parts[0]}.{parts[1]}.{parts[2]}.253",
                f"{parts[0]}.{parts[1]}.{parts[2]}.252",
            ])
        
        return variants

    async def improved_ip_test(self, domain, ip):
        """IP test with Host header"""
        try:
            headers = {
                'Host': domain,
                'User-Agent': self.get_random_ua(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            # Try HTTP with Host header
            async with self.session.get(f"http://{ip}", headers=headers, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    # Check if it's not a default page
                    if len(content) > 1000:  # Reasonable content length
                        return True
            
            return False
            
        except Exception:
            return False

    # 

    
    async def header_manipulation(self, domain):
        """Header Manipulation for Firewall Bypass"""
        print(f"{Colors.GREEN}[+] PHASE 3:  Header Manipulation{Colors.END}")
    
        header_payloads = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Forwarded-Host': domain},
            {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'},
            {'Referer': 'https://www.google.com/'},
            {'X-Forwarded-Proto': 'https'},
            {'X-Forwarded-Port': '443'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Cluster-Client-IP': '127.0.0.1'},
            {'X-Azure-ClientIP': '127.0.0.1'},
            {'X-AWS-ELB-Client-IP': '127.0.0.1'},
            {'CF-RAY': 'fake-ray-id'},
            {'X-Amz-Cf-Pop': 'LAX50-C1'},
            {'X-Amz-Cf-Id': 'fake-cf-id'},
            {'X-Edge-Location': 'lax'},
            {'X-Cache': 'Hit from cloudfront'},
            {'X-Content-Type-Options': 'nosniff'},
            {'X-Frame-Options': 'SAMEORIGIN'},
            {'X-XSS-Protection': '1; mode=block'},
            {'Strict-Transport-Security': 'max-age=31536000'},
            {'Content-Security-Policy': "default-src 'self'"},
            {'X-Corporate-Proxy': 'internal'},
            {'X-Internal-Request': 'true'},
            {'X-Corp-Network': 'trusted'},
            {'X-Proxy-User': 'admin'},
            {'X-Auth-Key': 'internal'},
            {'X-Debug': 'false'},
            {'X-Development': 'false'},
            {'X-Staging': 'false'},
            {'X-Env': 'production'},
            {'X-App-Version': '1.0.0'},
            {'X-LB-Health': 'healthy'},
            {'X-Backend-Server': 'server01'},
            {'X-Server-Pool': 'production'},
            {'X-Load-Balancer': 'aws-elb'},
            {'X-Mobile-App': 'false'},
            {'X-App-Platform': 'web'},
            {'X-Device-ID': 'desktop-web'},
            {'X-API-Key': 'legacy-key'},
            {'X-Cache-Bypass': 'true'},
            {'X-No-Cache': '1'},
            {'Cache-Control': 'no-cache, no-store'},
            {'Pragma': 'no-cache'},
            {'X-AWS-Request-ID': 'fake-request-id'},
            {'X-AWS-Region': 'us-east-1'},
            {'X-AWS-ALB': 'app/load-balancer/fake-id'},
            {'X-Google-Real-IP': '127.0.0.1'},
            {'X-Cloud-Trace-Context': 'fake-trace-id'},
            {'X-Goog-IAP-Profile': 'fake-profile'},
            {'X-Azure-Ref': 'fake-azure-ref'},
            {'X-Azure-SocketIP': '127.0.0.1'},
            {'X-Azure-FDID': 'fake-front-door-id'},
            {'CF-IPCountry': 'US'},
            {'CF-Visitor': '{"scheme":"https"}'},
            {'CF-Worker': 'production'},
            {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'},
            {'User-Agent': 'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'},
            {'User-Agent': 'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)'},
            {'User-Agent': 'FacebookExternalHit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'},
            {'User-Agent': 'Twitterbot/1.0'},
            {'User-Agent': 'LinkedInBot/1.0 (compatible; Mozilla/5.0; Jakarta Commons-HttpClient/3.1 +http://www.linkedin.com)'},
            {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'},
            {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'},
            {'X-Bypass-Firewall': 'true'},
            {'X-Security-Scan': 'completed'},
            {'X-Pentest-Approved': 'true'},
            {'X-Whitehat-Scan': 'authorized'},
            {'X-API-Version': 'v1'},
            {'X-API-Secret': 'legacy-secret'},
            {'X-Gateway-API': 'internal'},
            {'X-Microservice-Name': 'auth-service'},
            {'X-Mobile-Gateway': 'production'},
            {'X-Device-Type': 'web'},
            {'X-Platform': 'web'},
            {'X-Requested-With': 'XMLHttpRequest'},
            {'X-HTTP-Method-Override': 'GET'},
            {'X-CSRF-Token': 'legacy-token'},
            {'X-Monitoring': 'false'},
            {'X-Health-Check': 'false'},
            {'X-Uptime-Monitor': 'false'},
            {'X-Country-Code': 'US'},
            {'X-City': 'Los Angeles'},
            {'X-Region': 'CA'},
            {'X-Timezone': 'America/Los_Angeles'},
            {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1'},
            {'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36'},
            {'User-Agent': 'curl/7.68.0'},
            {'User-Agent': 'Wget/1.20.3 (linux-gnu)'},
        ]
        
        working_headers = []
        print(f"{Colors.WHITE}[*] Testing {len(header_payloads)} header combinations{Colors.END}")
        
        for headers in header_payloads:
            header_name = list(headers.keys())[0]
            
            try:
                if await self.real_header_test(domain, headers):
                    working_headers.append(headers)
                    print(f"{Colors.WHITE}[-] {header_name:<40} {Colors.GREEN}Bypass Success{Colors.END}")  # FIXED: Colors.GREEN
                else:
                    print(f"{Colors.WHITE}[-] {header_name:<40} {Colors.RED}Bypass Failed{Colors.END}")
            
            except Exception as e:
                print(f"{Colors.WHITE}[-] {header_name:<40} {Colors.RED}Test Error{Colors.END}")
            
            await asyncio.sleep(0.2)
        
        return working_headers

    async def real_header_test(self, domain, headers):
        """header test"""
        try:
            default_headers = {
                'User-Agent': self.get_random_ua(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br'
            }
            default_headers.update(headers)
            
            async with self.session.get(f"https://{domain}", headers=default_headers, timeout=8, ssl=False) as response:
                return response.status == 200
                
        except Exception:
            return False

    # 
    
    
    async def ultimate_bypass(self, domain, output_file=None):
        """Ultimate bypass attack"""
        print(f"{Colors.CYAN}[*] Starting Ultimate Bypass Attack{Colors.END}")
        print(f"{Colors.CYAN}[*] Target: {domain}{Colors.END}")
        
        await self.init_session()
        
        try:
            # Detect firewall
            firewall, confidence = await self.detector.detect_firewall(domain)
            
            # Execute all bypass methods
            all_results = {}
            
            # Phase 1: Smart Subdomain Validation
            valid_subs = await self.smart_subdomain_validation(domain)
            all_results['subdomains'] = await self.test_valid_subdomains(domain, valid_subs)
            
            # Phase 2: DNS History Bypass
            all_results['dns_history'] = await self.dns_history_bypass(domain)
            
            # Phase 3: Header Manipulation 
            all_results['headers'] = await self.header_manipulation(domain)
            
            # Save results
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(all_results, f, indent=2)
                print(f"{Colors.GREEN}[+] Results saved to: {output_file}{Colors.END}")
            
            # Display results
            self.display_results(all_results, domain, firewall)
            
            return all_results
            
        except Exception as e:
            print(f"{Colors.RED}[!] Critical error: {e}{Colors.END}")
            return {}
        finally:
            await self.close_session()

    def display_results(self, results, domain, firewall):
        """Display results"""
        print(f"\n{Colors.GREEN}{'-'*60}{Colors.END}")
        print(f"{Colors.GREEN}[+] BYPASS COMPLETED{Colors.END}")
        print(f"{Colors.GREEN}{'-'*60}{Colors.END}")
        
        total_success = 0
        for method, items in results.items():
            success_count = len(items)
            total_success += success_count
            
            status_color = Colors.GREEN if success_count > 0 else Colors.RED
            status_icon = "[+]" if success_count > 0 else "[-]"
            
            print(f"{status_color}{status_icon} {method.upper():<15} : {success_count:>2} bypasses{Colors.END}")
        
        print(f"{Colors.GREEN}{'-'*60}{Colors.END}")
        print(f"{Colors.GREEN}[*] TOTAL BYPASSES: {total_success}{Colors.END}")
        
        if total_success > 0:
            print(f"{Colors.GREEN}[*] FIREWALL BYPASS SUCCESSFUL!{Colors.END}")
        else:
            print(f"{Colors.RED}[!] No bypass methods succeeded{Colors.END}")

def show_usage():
    usage = f"""
{Colors.WHITE}
EVILWAF:
--------

{Colors.WHITE}Usage:{Colors.END}
  python3 evilwaf.py -d website.com -o results.json
  python3 evilwaf.py -d example.com

{Colors.WHITE}Options:{Colors.END}
  -d, --domain    Target domain (required)
  -o, --output    Save results to JSON file
  -h, --help      Show this help message
  -u, --update    Show update info  


{Colors.WHITE}Examples:{Colors.END}
  python3 evilwaf.py --update
  python3 evilwaf.py -d example.com
  python3 evilwaf.py -d website.com -o results.json
{Colors.END}
"""
    print(usage)

def main():
    parser = argparse.ArgumentParser(description='EVILWAF-Firewall Edition', add_help=False)
    parser.add_argument('-d', '--domain', help='Target domain to bypass')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-u', '--update', action='store_true', help='Update EvilWAF to latest version')  
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    
    args = parser.parse_args()
    
    
    
    
    if args.update:
        from core.updater import EvilWAFUpdater
        updater = EvilWAFUpdater()
        success = updater.perform_update()
        sys.exit(0 if success else 1)
     
    
    
    if args.help or not args.domain:
        show_banner()
        show_usage()
        sys.exit(0)
    
    show_banner()
    
    print(f"{Colors.GREEN}[+] Target: {args.domain}{Colors.END}")
    
    tool = EvilWAFBypass()
    
    try:
        results = asyncio.run(tool.ultimate_bypass(args.domain, args.output))
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")

if __name__ == "__main__":
    main() 
