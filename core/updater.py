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
COPYRIGHT (c) 2025

         Happy ethical hacking!
"""

import os
import sys
import requests
import json
import subprocess
from colorama import Fore, Style, init

init(autoreset=True)

class EvilWAFUpdater:
    def __init__(self):
        self.current_version = "2.1"
        self.github_repo = "matrixleons/evilwaf"
        self.update_url = f"https://api.github.com/repos/{self.github_repo}/releases/latest"
        self.local_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
    def check_for_updates(self):
        """Check for available updates"""
        print(f"{Fore.YELLOW}[*] Checking for updates...{Style.RESET_ALL}")
        
        try:
            response = requests.get(self.update_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get('tag_name', '').replace('v', '')
                
                if self.is_newer_version(latest_version):
                    print(f"{Fore.GREEN}[+] New version available: {latest_version}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Current version: {self.current_version}{Style.RESET_ALL}")
                    return True, latest_version, data
                else:
                    print(f"{Fore.GREEN}[+] You have the latest version ({self.current_version}){Style.RESET_ALL}")
                    return False, self.current_version, None
            else:
                print(f"{Fore.RED}[-] Failed to check updates: HTTP {response.status_code}{Style.RESET_ALL}")
                return False, self.current_version, None
                
        except Exception as e:
            print(f"{Fore.RED}[-] Update check failed: {e}{Style.RESET_ALL}")
            return False, self.current_version, None
    
    def is_newer_version(self, latest_version):
        """Check if latest version is newer than current"""
        try:
            current_parts = list(map(int, self.current_version.split('.')))
            latest_parts = list(map(int, latest_version.split('.')))
            
            for i in range(max(len(current_parts), len(latest_parts))):
                current_part = current_parts[i] if i < len(current_parts) else 0
                latest_part = latest_parts[i] if i < len(latest_parts) else 0
                
                if latest_part > current_part:
                    return True
                elif latest_part < current_part:
                    return False
            return False
        except:
            return False
    
    def backup_current_version(self):
        """Backup current version before update"""
        backup_dir = os.path.join(self.local_path, 'backup')
        os.makedirs(backup_dir, exist_ok=True)
        
        try:
            # Backup main script
            main_script = os.path.join(self.local_path, 'evilwaf.py')
            if os.path.exists(main_script):
                backup_file = os.path.join(backup_dir, 'evilwaf.py.backup')
                with open(main_script, 'r') as source, open(backup_file, 'w') as target:
                    target.write(source.read())
                print(f"{Fore.GREEN}[+] Backup created: {backup_file}{Style.RESET_ALL}")
            
            # Backup core modules
            core_dir = os.path.join(self.local_path, 'core')
            if os.path.exists(core_dir):
                import shutil
                backup_core = os.path.join(backup_dir, 'core_backup')
                if os.path.exists(backup_core):
                    shutil.rmtree(backup_core)
                shutil.copytree(core_dir, backup_core)
                print(f"{Fore.GREEN}[+] Core modules backed up{Style.RESET_ALL}")
                
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Backup failed: {e}{Style.RESET_ALL}")
            return False
    
    def perform_update(self):
        """Perform the update process"""
        print(f"{Fore.CYAN}[*] Starting update process...{Style.RESET_ALL}")
        
        # Check for updates first
        update_available, latest_version, update_data = self.check_for_updates()
        
        if not update_available:
            print(f"{Fore.YELLOW}[!] No updates available{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.YELLOW}[?] Do you want to update to version {latest_version}? (y/N): {Style.RESET_ALL}", end='')
        choice = input().strip().lower()
        
        if choice not in ['y', 'yes']:
            print(f"{Fore.YELLOW}[!] Update cancelled{Style.RESET_ALL}")
            return False
        
        # Create backup
        if not self.backup_current_version():
            print(f"{Fore.RED}[-] Cannot proceed without backup{Style.RESET_ALL}")
            return False
        
        try:
            print(f"{Fore.YELLOW}[*] Downloading update...{Style.RESET_ALL}")
            
            # Get download URL from GitHub release
            download_url = None
            for asset in update_data.get('assets', []):
                if asset.get('name', '').endswith('.zip') or asset.get('name', '').endswith('.tar.gz'):
                    download_url = asset.get('browser_download_url')
                    break
            
            if not download_url:
                # Fallback: clone latest version
                return self.update_via_git_clone()
            
            # Download and extract update
            return self.download_and_extract(download_url, latest_version)
            
        except Exception as e:
            print(f"{Fore.RED}[-] Update failed: {e}{Style.RESET_ALL}")
            return self.restore_backup()
    
    def update_via_git_clone(self):
        """Update via git clone method"""
        try:
            temp_dir = "/tmp/evilwaf_update"
            
            # Clone latest version
            clone_cmd = f"git clone https://github.com/{self.github_repo}.git {temp_dir}"
            result = subprocess.run(clone_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"{Fore.RED}[-] Git clone failed: {result.stderr}{Style.RESET_ALL}")
                return False
            
            # Copy files to current location
            import shutil
            for item in os.listdir(temp_dir):
                if item == '.git':
                    continue
                
                src_path = os.path.join(temp_dir, item)
                dst_path = os.path.join(self.local_path, item)
                
                if os.path.isdir(src_path):
                    if os.path.exists(dst_path):
                        shutil.rmtree(dst_path)
                    shutil.copytree(src_path, dst_path)
                else:
                    shutil.copy2(src_path, dst_path)
            
            # Cleanup
            shutil.rmtree(temp_dir)
            
            print(f"{Fore.GREEN}[+] Update completed successfully!{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[-] Git update failed: {e}{Style.RESET_ALL}")
            return False
    
    def download_and_extract(self, download_url, version):
        """Download and extract update"""
        try:
            import tempfile
            import zipfile
            
            # Download update
            response = requests.get(download_url, stream=True)
            if response.status_code != 200:
                print(f"{Fore.RED}[-] Download failed: HTTP {response.status_code}{Style.RESET_ALL}")
                return False
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_path = temp_file.name
            
            # Extract update
            with zipfile.ZipFile(temp_path, 'r') as zip_ref:
                extract_path = tempfile.mkdtemp()
                zip_ref.extractall(extract_path)
            
            # Copy files
            self.copy_update_files(extract_path)
            
            # Cleanup
            os.unlink(temp_path)
            import shutil
            shutil.rmtree(extract_path)
            
            print(f"{Fore.GREEN}[+] Update to version {version} completed!{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[-] Download/extract failed: {e}{Style.RESET_ALL}")
            return False
    
    def copy_update_files(self, extract_path):
        """Copy updated files to current location"""
        import shutil
        
        # Find the actual extracted directory
        for item in os.listdir(extract_path):
            item_path = os.path.join(extract_path, item)
            if os.path.isdir(item_path) and 'evilwaf' in item.lower():
                extract_path = item_path
                break
        
        # Copy files
        for item in os.listdir(extract_path):
            if item == '.git' or item == 'README.md':
                continue
                
            src_path = os.path.join(extract_path, item)
            dst_path = os.path.join(self.local_path, item)
            
            if os.path.isdir(src_path):
                if os.path.exists(dst_path):
                    shutil.rmtree(dst_path)
                shutil.copytree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)
    
    def restore_backup(self):
        """Restore from backup if update fails"""
        print(f"{Fore.YELLOW}[*] Restoring from backup...{Style.RESET_ALL}")
        
        backup_dir = os.path.join(self.local_path, 'backup')
        try:
            import shutil
            
            # Restore main script
            backup_file = os.path.join(backup_dir, 'evilwaf.py.backup')
            if os.path.exists(backup_file):
                shutil.copy2(backup_file, os.path.join(self.local_path, 'evilwaf.py'))
            
            # Restore core modules
            backup_core = os.path.join(backup_dir, 'core_backup')
            if os.path.exists(backup_core):
                core_dir = os.path.join(self.local_path, 'core')
                if os.path.exists(core_dir):
                    shutil.rmtree(core_dir)
                shutil.copytree(backup_core, core_dir)
            
            print(f"{Fore.GREEN}[+] Backup restored successfully{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[-] Backup restoration failed: {e}{Style.RESET_ALL}")
            return False

def main():
    """Main update function"""
    updater = EvilWAFUpdater()
    return updater.perform_update()

if __name__ == "__main__":
    main()
