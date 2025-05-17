#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import re
import json
import dns.resolver
import socket
import whois
import argparse
import sys
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class WordPressScanner:
    def __init__(self, target_url):
        self.target_url = self._normalize_url(target_url)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.results = {
            'url': self.target_url,
            'is_wordpress': False,
            'theme': None,
            'plugins': [],
            'vulnerabilities': [],
            'improvements': [],
            'hosting': None,
            'dns_zones': [],
            'wordpress_version': None,
            'additional_info': {},
            'listable_directories': [],
            'sensitive_files': [],
            'security_headers': {},
            'wp_config_backups': [],
            'exposed_files': {},
            'js_css_versions': [],
            'sitemap_robots': {}
        }

    def _normalize_url(self, url):
        """Ensure URL has a scheme and no trailing slash"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def scan(self):
        """Run the complete WordPress scan"""
        print(f"{Fore.CYAN}[*] Iniciando análise WordPress para {self.target_url}{Style.RESET_ALL}")

        try:
            # Check if the site is WordPress
            if not self._check_wordpress():
                print(f"{Fore.RED}[!] O alvo não parece ser um site WordPress{Style.RESET_ALL}")
                return self.results

            # Get WordPress version
            self._get_wordpress_version()

            # Get theme information
            self._get_theme()

            # Get plugins
            self._get_plugins()

            # Check for vulnerabilities
            self._check_vulnerabilities()

            # Suggest improvements
            self._suggest_improvements()

            # Get hosting information
            self._get_hosting_info()

            # Get DNS zones
            self._get_dns_zones()

            # Check for WordPress debug mode
            self._check_debug_mode()

            # Check for SSL/TLS security
            self._check_ssl_security()

            # Check for user enumeration vulnerability
            self._check_user_enumeration()

            # Detect WAF (Web Application Firewall)
            self._detect_waf()

            # Check for listable directories
            self._check_listable_directories()

            # Check for sensitive files
            self._check_sensitive_files()

            # Check readme.html and license.txt
            self._check_readme_license()

            # Check security headers
            self._check_security_headers()

            # Check for PHP execution in uploads directory
            self._check_php_execution()

            # Check for login protection (2FA/CAPTCHA)
            self._check_login_protection()

            # Check for automatic updates
            self._check_auto_updates()

            # Check for nulled plugins/themes
            self._check_nulled_plugins_themes()

            # Check sitemap.xml and robots.txt
            self._check_sitemap_robots()

            # Check JS/CSS versions
            self._check_js_css_versions()

            print(f"{Fore.GREEN}[+] Análise concluída com sucesso{Style.RESET_ALL}")
            return self.results

        except Exception as e:
            print(f"{Fore.RED}[!] Error during scan: {str(e)}{Style.RESET_ALL}")
            return self.results

    def _check_wordpress(self):
        """Check if the target is a WordPress site"""
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for WordPress meta generator tag
            meta_generator = soup.find('meta', {'name': 'generator'})
            if meta_generator and 'wordpress' in meta_generator.get('content', '').lower():
                self.results['is_wordpress'] = True
                print(f"{Fore.GREEN}[+] Site WordPress detectado{Style.RESET_ALL}")
                return True

            # Check for wp-content directory
            if 'wp-content' in response.text or 'wp-includes' in response.text:
                self.results['is_wordpress'] = True
                print(f"{Fore.GREEN}[+] Site WordPress detectado{Style.RESET_ALL}")
                return True

            # Check for login page
            login_response = requests.get(f"{self.target_url}/wp-login.php", headers=self.headers, timeout=10)
            if login_response.status_code == 200 and ('user_login' in login_response.text or 'wp-submit' in login_response.text):
                self.results['is_wordpress'] = True
                print(f"{Fore.GREEN}[+] Site WordPress detectado{Style.RESET_ALL}")
                return True

            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar se é WordPress: {str(e)}{Style.RESET_ALL}")
            return False

    def _get_wordpress_version(self):
        """Get WordPress version"""
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check meta generator tag
            meta_generator = soup.find('meta', {'name': 'generator'})
            if meta_generator and 'wordpress' in meta_generator.get('content', '').lower():
                version = re.search(r'WordPress (\d+\.\d+(?:\.\d+)?)', meta_generator['content'])
                if version:
                    self.results['wordpress_version'] = version.group(1)
                    print(f"{Fore.GREEN}[+] Versão do WordPress: {version.group(1)}{Style.RESET_ALL}")
                    return

            # Check readme.html
            readme_response = requests.get(f"{self.target_url}/readme.html", headers=self.headers, timeout=10)
            if readme_response.status_code == 200:
                version = re.search(r'Version (\d+\.\d+(?:\.\d+)?)', readme_response.text)
                if version:
                    self.results['wordpress_version'] = version.group(1)
                    print(f"{Fore.GREEN}[+] Versão do WordPress: {version.group(1)}{Style.RESET_ALL}")
                    return

            # Check feed
            feed_response = requests.get(f"{self.target_url}/feed/", headers=self.headers, timeout=10)
            if feed_response.status_code == 200:
                version = re.search(r'generator="WordPress/(\d+\.\d+(?:\.\d+)?)"', feed_response.text)
                if version:
                    self.results['wordpress_version'] = version.group(1)
                    print(f"{Fore.GREEN}[+] Versão do WordPress: {version.group(1)}{Style.RESET_ALL}")
                    return

            print(f"{Fore.YELLOW}[!] Versão do WordPress não encontrada{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao obter versão do WordPress: {str(e)}{Style.RESET_ALL}")

    def _get_theme(self):
        """Get WordPress theme information"""
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Method 1: Check style links
            for link in soup.find_all('link', {'rel': 'stylesheet'}):
                href = link.get('href', '')
                theme_match = re.search(r'wp-content/themes/([^/]+)', href)
                if theme_match:
                    theme_name = theme_match.group(1)
                    self.results['theme'] = {
                        'name': theme_name,
                        'url': href
                    }
                    print(f"{Fore.GREEN}[+] Tema detectado: {theme_name}{Style.RESET_ALL}")
                    return

            # Method 2: Check HTML body classes
            body_tag = soup.find('body')
            if body_tag and body_tag.get('class'):
                body_classes = ' '.join(body_tag['class'])
                theme_match = re.search(r'theme-([^\s]+)', body_classes)
                if theme_match:
                    theme_name = theme_match.group(1)
                    self.results['theme'] = {
                        'name': theme_name,
                        'detected_from': 'body_class'
                    }
                    print(f"{Fore.GREEN}[+] Tema detectado: {theme_name}{Style.RESET_ALL}")
                    return

            print(f"{Fore.YELLOW}[!] Tema WordPress não detectado{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao detectar tema: {str(e)}{Style.RESET_ALL}")

    def _get_plugins(self):
        """Get WordPress plugins"""
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            plugins = set()

            # Method 1: Check script and style tags
            for resource in soup.find_all(['script', 'link']):
                src = resource.get('src') or resource.get('href') or ''
                plugin_match = re.search(r'wp-content/plugins/([^/]+)', src)
                if plugin_match:
                    plugin_name = plugin_match.group(1)
                    plugins.add(plugin_name)

            # Method 2: Try to access common plugin directories
            for plugin in plugins:
                try:
                    plugin_url = f"{self.target_url}/wp-content/plugins/{plugin}/"
                    plugin_response = requests.head(plugin_url, headers=self.headers, timeout=5)
                    status = "Active" if plugin_response.status_code == 200 else "Unknown"

                    self.results['plugins'].append({
                        'name': plugin,
                        'status': status,
                        'url': plugin_url
                    })
                    status_pt = "Ativo" if status == "Active" else "Desconhecido"
                    print(f"{Fore.GREEN}[+] Plugin detectado: {plugin} ({status_pt}){Style.RESET_ALL}")
                except:
                    self.results['plugins'].append({
                        'name': plugin,
                        'status': "Unknown",
                        'url': f"{self.target_url}/wp-content/plugins/{plugin}/"
                    })
                    print(f"{Fore.GREEN}[+] Plugin detectado: {plugin} (Status desconhecido){Style.RESET_ALL}")

            # Method 3: Try to access plugin list from wp-json API
            try:
                api_response = requests.get(f"{self.target_url}/wp-json/wp/v2/plugins", headers=self.headers, timeout=5)
                if api_response.status_code == 200:
                    api_plugins = api_response.json()
                    for plugin in api_plugins:
                        if isinstance(plugin, dict) and 'name' in plugin:
                            self.results['plugins'].append({
                                'name': plugin['name'],
                                'status': "Active" if plugin.get('status') == 'active' else "Inactive",
                                'version': plugin.get('version', 'Unknown')
                            })
                            print(f"{Fore.GREEN}[+] Plugin detectado via API: {plugin['name']}{Style.RESET_ALL}")
            except:
                pass

            if not self.results['plugins']:
                print(f"{Fore.YELLOW}[!] Nenhum plugin WordPress detectado{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao detectar plugins: {str(e)}{Style.RESET_ALL}")

    def _check_vulnerabilities(self):
        """Check for known vulnerabilities"""
        # This is a simplified version. In a real-world scenario, you would use a vulnerability database.
        try:
            # Check WordPress version vulnerabilities
            if self.results['wordpress_version']:
                version = self.results['wordpress_version']
                if version.startswith('3.') or version.startswith('4.') or version.startswith('2.'):
                    self.results['vulnerabilities'].append({
                        'type': 'wordpress_core',
                        'description': f'WordPress {version} está desatualizado e pode conter vulnerabilidades de segurança',
                        'recommendation': 'Atualize para a versão mais recente do WordPress'
                    })
                    print(f"{Fore.RED}[!] Vulnerabilidade: WordPress {version} está desatualizado{Style.RESET_ALL}")

            # Check for vulnerable plugins (simplified example)
            vulnerable_plugins = {
                'contact-form-7': {'versions': ['<5.3.2'], 'description': 'Vulnerabilidade XSS em versões antigas'},
                'wp-super-cache': {'versions': ['<1.7.2'], 'description': 'Vulnerabilidade RCE autenticada'},
                'woocommerce': {'versions': ['<5.5.1'], 'description': 'Vulnerabilidade de injeção SQL em versões antigas'}
            }

            for plugin in self.results['plugins']:
                plugin_name = plugin['name'].lower()
                if plugin_name in vulnerable_plugins:
                    self.results['vulnerabilities'].append({
                        'type': 'plugin',
                        'name': plugin_name,
                        'description': vulnerable_plugins[plugin_name]['description'],
                        'recommendation': f'Atualize {plugin_name} para a versão mais recente'
                    })
                    print(f"{Fore.RED}[!] Vulnerabilidade: {plugin_name} pode ser vulnerável - {vulnerable_plugins[plugin_name]['description']}{Style.RESET_ALL}")

            if not self.results['vulnerabilities']:
                print(f"{Fore.GREEN}[+] Nenhuma vulnerabilidade óbvia detectada{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar vulnerabilidades: {str(e)}{Style.RESET_ALL}")

    def _suggest_improvements(self):
        """Suggest security improvements"""
        try:
            # Check for exposed wp-config.php
            config_response = requests.head(f"{self.target_url}/wp-config.php", headers=self.headers, timeout=5)
            if config_response.status_code != 404:
                self.results['improvements'].append({
                    'type': 'critical',
                    'description': 'Arquivo wp-config.php pode estar acessível',
                    'recommendation': 'Bloqueie o acesso ao wp-config.php na configuração do seu servidor web'
                })
                print(f"{Fore.RED}[!] Melhoria necessária: wp-config.php pode estar acessível{Style.RESET_ALL}")

            # Check for directory listing
            wp_includes_response = requests.get(f"{self.target_url}/wp-includes/", headers=self.headers, timeout=5)
            if wp_includes_response.status_code == 200 and 'Index of' in wp_includes_response.text:
                self.results['improvements'].append({
                    'type': 'medium',
                    'description': 'Listagem de diretórios está habilitada',
                    'recommendation': 'Desabilite a listagem de diretórios na configuração do seu servidor web'
                })
                print(f"{Fore.YELLOW}[!] Melhoria necessária: Listagem de diretórios está habilitada{Style.RESET_ALL}")

            # Check for readme.html
            readme_response = requests.head(f"{self.target_url}/readme.html", headers=self.headers, timeout=5)
            if readme_response.status_code == 200:
                self.results['improvements'].append({
                    'type': 'low',
                    'description': 'Arquivo readme.html está acessível',
                    'recommendation': 'Remova ou restrinja o acesso ao readme.html'
                })
                print(f"{Fore.YELLOW}[!] Melhoria necessária: readme.html está acessível{Style.RESET_ALL}")

            # Check for XML-RPC
            xmlrpc_response = requests.head(f"{self.target_url}/xmlrpc.php", headers=self.headers, timeout=5)
            if xmlrpc_response.status_code == 200:
                self.results['improvements'].append({
                    'type': 'medium',
                    'description': 'XML-RPC está habilitado',
                    'recommendation': 'Desabilite o XML-RPC se não for necessário ou restrinja o acesso'
                })
                print(f"{Fore.YELLOW}[!] Melhoria necessária: XML-RPC está habilitado{Style.RESET_ALL}")

            if not self.results['improvements']:
                print(f"{Fore.GREEN}[+] Nenhuma melhoria óbvia necessária{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao sugerir melhorias: {str(e)}{Style.RESET_ALL}")

    def _get_hosting_info(self):
        """Get hosting information"""
        try:
            parsed_url = urlparse(self.target_url)
            domain = parsed_url.netloc

            # Get IP address
            ip_address = socket.gethostbyname(domain)

            # Try to get WHOIS information
            try:
                domain_info = whois.whois(domain)
                registrar = domain_info.registrar
                creation_date = domain_info.creation_date
                expiration_date = domain_info.expiration_date

                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]

                self.results['hosting'] = {
                    'ip': ip_address,
                    'registrar': registrar,
                    'creation_date': str(creation_date) if creation_date else 'Desconhecida',
                    'expiration_date': str(expiration_date) if expiration_date else 'Desconhecida'
                }
            except:
                self.results['hosting'] = {
                    'ip': ip_address,
                    'registrar': 'Desconhecido',
                    'creation_date': 'Desconhecida',
                    'expiration_date': 'Desconhecida'
                }

            # Try to get server information from headers
            response = requests.head(self.target_url, headers=self.headers, timeout=10)
            server = response.headers.get('Server', 'Desconhecido')
            self.results['hosting']['server'] = server

            print(f"{Fore.GREEN}[+] Informações de hospedagem: IP {ip_address}, Servidor {server}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao obter informações de hospedagem: {str(e)}{Style.RESET_ALL}")
            self.results['hosting'] = {'error': str(e)}

    def _get_dns_zones(self):
        """Get DNS zone information"""
        try:
            parsed_url = urlparse(self.target_url)
            domain = parsed_url.netloc

            # Common DNS record types to check
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']

            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records = [str(answer) for answer in answers]

                    self.results['dns_zones'].append({
                        'type': record_type,
                        'records': records
                    })

                    print(f"{Fore.GREEN}[+] Registros DNS {record_type}: {', '.join(records)}{Style.RESET_ALL}")
                except Exception as e:
                    # Skip if no records of this type
                    pass

            if not self.results['dns_zones']:
                print(f"{Fore.YELLOW}[!] Nenhum registro DNS encontrado{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao obter informações de DNS: {str(e)}{Style.RESET_ALL}")

    def _check_debug_mode(self):
        """Check if WordPress debug mode is enabled"""
        try:
            # Check for debug.log file
            debug_log_response = requests.head(f"{self.target_url}/wp-content/debug.log", headers=self.headers, timeout=5)
            if debug_log_response.status_code == 200:
                self.results['improvements'].append({
                    'type': 'critical',
                    'description': 'Arquivo debug.log acessível - Modo de depuração pode estar ativado',
                    'recommendation': 'Desative o modo de depuração do WordPress ou bloqueie o acesso ao arquivo debug.log'
                })
                print(f"{Fore.RED}[!] Vulnerabilidade: Arquivo debug.log acessível{Style.RESET_ALL}")

            # Try to check for debug information in the page source
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            if 'WP_DEBUG' in response.text or 'Warning:' in response.text and 'on line' in response.text:
                self.results['improvements'].append({
                    'type': 'critical',
                    'description': 'Modo de depuração do WordPress parece estar ativado',
                    'recommendation': 'Desative o modo de depuração em wp-config.php definindo WP_DEBUG como false'
                })
                print(f"{Fore.RED}[!] Vulnerabilidade: Modo de depuração do WordPress ativado{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar modo de depuração: {str(e)}{Style.RESET_ALL}")

    def _check_ssl_security(self):
        """Check SSL/TLS security"""
        try:
            parsed_url = urlparse(self.target_url)
            if parsed_url.scheme != 'https':
                self.results['improvements'].append({
                    'type': 'critical',
                    'description': 'Site não está usando HTTPS',
                    'recommendation': 'Implemente SSL/TLS e redirecione todo o tráfego para HTTPS'
                })
                print(f"{Fore.RED}[!] Vulnerabilidade: Site não está usando HTTPS{Style.RESET_ALL}")
                return

            # Check SSL certificate
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=True)

            # Check for HSTS header
            if 'Strict-Transport-Security' not in response.headers:
                self.results['improvements'].append({
                    'type': 'medium',
                    'description': 'Cabeçalho HSTS não implementado',
                    'recommendation': 'Implemente o cabeçalho HTTP Strict Transport Security (HSTS)'
                })
                print(f"{Fore.YELLOW}[!] Melhoria: Cabeçalho HSTS não implementado{Style.RESET_ALL}")

            # Add SSL info to results
            self.results['additional_info']['ssl'] = {
                'enabled': True,
                'hsts': 'Strict-Transport-Security' in response.headers
            }

            print(f"{Fore.GREEN}[+] Segurança SSL verificada{Style.RESET_ALL}")

        except requests.exceptions.SSLError:
            self.results['improvements'].append({
                'type': 'critical',
                'description': 'Erro de certificado SSL',
                'recommendation': 'Verifique e corrija o certificado SSL do site'
            })
            print(f"{Fore.RED}[!] Vulnerabilidade: Erro de certificado SSL{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar segurança SSL: {str(e)}{Style.RESET_ALL}")

    def _check_user_enumeration(self):
        """Check for user enumeration vulnerability"""
        try:
            # Try to access author page with ID 1
            author_response = requests.get(f"{self.target_url}/?author=1", headers=self.headers, timeout=10, allow_redirects=True)

            # Check if redirected to an author page or contains author information
            if 'author' in author_response.url or 'author' in author_response.text.lower():
                self.results['vulnerabilities'].append({
                    'type': 'wordpress_core',
                    'description': 'Vulnerabilidade de enumeração de usuários detectada',
                    'recommendation': 'Instale um plugin de segurança para bloquear a enumeração de usuários ou adicione regras personalizadas ao .htaccess'
                })
                print(f"{Fore.RED}[!] Vulnerabilidade: Enumeração de usuários possível{Style.RESET_ALL}")

            # Check REST API user enumeration
            api_response = requests.get(f"{self.target_url}/wp-json/wp/v2/users", headers=self.headers, timeout=5)
            if api_response.status_code == 200:
                try:
                    users_data = api_response.json()
                    if isinstance(users_data, list) and len(users_data) > 0:
                        self.results['vulnerabilities'].append({
                            'type': 'wordpress_api',
                            'description': 'API REST expõe informações de usuários',
                            'recommendation': 'Restrinja o acesso à API REST do WordPress para endpoints sensíveis'
                        })

                        # Store found users
                        users = []
                        for user in users_data:
                            if isinstance(user, dict) and 'name' in user:
                                users.append({
                                    'name': user.get('name', ''),
                                    'slug': user.get('slug', ''),
                                    'id': user.get('id', '')
                                })

                        if users:
                            self.results['additional_info']['users'] = users
                            print(f"{Fore.RED}[!] Vulnerabilidade: API REST expõe {len(users)} usuários{Style.RESET_ALL}")
                except:
                    pass

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar enumeração de usuários: {str(e)}{Style.RESET_ALL}")

    def _detect_waf(self):
        """Detect Web Application Firewall"""
        try:
            # Send a request with suspicious parameters to trigger WAF
            waf_test_url = f"{self.target_url}/?s=<script>alert(1)</script>"
            response = requests.get(waf_test_url, headers=self.headers, timeout=10)

            # Check for common WAF signatures in headers
            waf_detected = None

            # Check for Cloudflare
            if 'cf-ray' in response.headers or 'cloudflare' in response.headers.get('server', '').lower():
                waf_detected = 'Cloudflare'
            # Check for Sucuri
            elif 'sucuri' in response.headers.get('server', '').lower() or 'sucuri' in str(response.headers).lower():
                waf_detected = 'Sucuri'
            # Check for Wordfence (common WordPress WAF)
            elif 'wordfence' in response.text.lower():
                waf_detected = 'Wordfence'
            # Check for ModSecurity
            elif 'mod_security' in response.headers.get('server', '').lower() or 'modsecurity' in str(response.headers).lower():
                waf_detected = 'ModSecurity'

            if waf_detected:
                self.results['additional_info']['waf'] = {
                    'detected': True,
                    'name': waf_detected
                }
                print(f"{Fore.GREEN}[+] Firewall de Aplicação Web (WAF) detectado: {waf_detected}{Style.RESET_ALL}")
            else:
                self.results['additional_info']['waf'] = {
                    'detected': False
                }
                self.results['improvements'].append({
                    'type': 'medium',
                    'description': 'Nenhum Firewall de Aplicação Web (WAF) detectado',
                    'recommendation': 'Considere implementar um WAF como Cloudflare, Sucuri ou Wordfence para proteção adicional'
                })
                print(f"{Fore.YELLOW}[!] Nenhum Firewall de Aplicação Web (WAF) detectado{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao detectar WAF: {str(e)}{Style.RESET_ALL}")

    def _check_listable_directories(self):
        """Check if common directories are listable"""
        try:
            common_dirs = [
                '/wp-content/',
                '/wp-content/uploads/',
                '/wp-content/plugins/',
                '/wp-content/themes/',
                '/wp-includes/',
                '/wp-admin/css/',
                '/wp-admin/js/',
                '/wp-admin/images/'
            ]

            for directory in common_dirs:
                try:
                    dir_url = f"{self.target_url}{directory}"
                    response = requests.get(dir_url, headers=self.headers, timeout=5)

                    # Check if directory listing is enabled
                    if response.status_code == 200 and ('Index of' in response.text or '<title>Index of' in response.text):
                        self.results['listable_directories'].append({
                            'url': dir_url,
                            'status': 'Listable'
                        })

                        self.results['vulnerabilities'].append({
                            'type': 'directory_listing',
                            'description': f'Listagem de diretório habilitada em {directory}',
                            'recommendation': 'Desabilite a listagem de diretórios na configuração do seu servidor web'
                        })

                        print(f"{Fore.RED}[!] Vulnerabilidade: Listagem de diretório habilitada em {directory}{Style.RESET_ALL}")
                except Exception as e:
                    # Skip if directory can't be accessed
                    pass

            if not self.results['listable_directories']:
                print(f"{Fore.GREEN}[+] Nenhum diretório com listagem habilitada detectado{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar diretórios listáveis: {str(e)}{Style.RESET_ALL}")

    def _check_sensitive_files(self):
        """Check for exposed sensitive files"""
        try:
            sensitive_files = [
                # Environment and configuration files
                '/.env',
                '/wp-config.php~',
                '/wp-config.php.bak',
                '/wp-config.php.old',
                '/wp-config.php.save',
                '/wp-config.php.swp',
                '/wp-config.php.swo',
                '/wp-config.txt',
                '/wp-config.php.txt',

                # Debug logs
                '/wp-content/debug.log',
                '/debug.log',

                # Version control
                '/.git/HEAD',
                '/.git/config',
                '/.gitignore',
                '/.svn/entries',

                # Backup files
                '/backup.zip',
                '/backup.sql',
                '/backup.tar.gz',
                '/wp-content/backup-db/',
                '/wp-content/backups/',

                # WordPress specific files
                '/wp-content/uploads/wp-config.php',
                '/wp-json/wp/v2/users',

                # Server configuration files
                '/.htaccess',
                '/.htaccess.bak',
                '/web.config',
                '/robots.txt',
                '/error_log'
            ]

            for file_path in sensitive_files:
                try:
                    file_url = f"{self.target_url}{file_path}"
                    response = requests.head(file_url, headers=self.headers, timeout=5)

                    if response.status_code == 200:
                        # For some files, we want to check the content
                        if file_path in ['/wp-config.php~', '/wp-config.php.bak', '/wp-config.php.old', 
                                        '/wp-config.php.save', '/wp-config.php.swp', '/wp-config.php.swo',
                                        '/wp-config.txt', '/wp-config.php.txt']:
                            self.results['wp_config_backups'].append(file_url)
                            self.results['vulnerabilities'].append({
                                'type': 'sensitive_file',
                                'description': f'Backup do arquivo wp-config.php exposto: {file_path}',
                                'recommendation': 'Remova ou bloqueie o acesso a backups do arquivo wp-config.php'
                            })
                            print(f"{Fore.RED}[!] Vulnerabilidade: Backup do wp-config.php exposto: {file_path}{Style.RESET_ALL}")
                        else:
                            # Add to exposed files with file type category
                            file_type = 'other'
                            if '.env' in file_path:
                                file_type = 'environment'
                            elif 'debug.log' in file_path:
                                file_type = 'debug_log'
                            elif '.git' in file_path or '.svn' in file_path:
                                file_type = 'version_control'
                            elif 'backup' in file_path:
                                file_type = 'backup'
                            elif 'wp-json' in file_path:
                                file_type = 'api'
                            elif '.htaccess' in file_path or 'web.config' in file_path:
                                file_type = 'server_config'

                            if file_type not in self.results['exposed_files']:
                                self.results['exposed_files'][file_type] = []

                            self.results['exposed_files'][file_type].append(file_url)

                            # Add vulnerability
                            self.results['vulnerabilities'].append({
                                'type': 'sensitive_file',
                                'description': f'Arquivo sensível exposto: {file_path}',
                                'recommendation': 'Remova ou bloqueie o acesso a arquivos sensíveis'
                            })
                            print(f"{Fore.RED}[!] Vulnerabilidade: Arquivo sensível exposto: {file_path}{Style.RESET_ALL}")
                except Exception as e:
                    # Skip if file can't be accessed
                    pass

            if not self.results['wp_config_backups'] and not self.results['exposed_files']:
                print(f"{Fore.GREEN}[+] Nenhum arquivo sensível exposto detectado{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar arquivos sensíveis: {str(e)}{Style.RESET_ALL}")

    def _check_readme_license(self):
        """Verify the presence and content of /readme.html and /license.txt"""
        try:
            # Check for readme.html
            readme_url = f"{self.target_url}/readme.html"
            readme_response = requests.get(readme_url, headers=self.headers, timeout=5)

            if readme_response.status_code == 200:
                # Check if it's a WordPress readme
                if 'WordPress' in readme_response.text:
                    # Try to extract version
                    version_match = re.search(r'Version (\d+\.\d+(?:\.\d+)?)', readme_response.text)
                    version = version_match.group(1) if version_match else "Desconhecida"

                    self.results['exposed_files']['readme'] = {
                        'url': readme_url,
                        'version': version
                    }

                    # Add as improvement rather than vulnerability
                    self.results['improvements'].append({
                        'type': 'low',
                        'description': f'Arquivo readme.html acessível (revela versão: {version})',
                        'recommendation': 'Remova ou bloqueie o acesso ao arquivo readme.html para evitar divulgação da versão'
                    })

                    print(f"{Fore.YELLOW}[!] Melhoria: readme.html acessível (revela versão: {version}){Style.RESET_ALL}")

                    # If we didn't have version info before, add it now
                    if not self.results['wordpress_version'] and version != "Desconhecida":
                        self.results['wordpress_version'] = version
                        print(f"{Fore.GREEN}[+] Versão do WordPress detectada via readme.html: {version}{Style.RESET_ALL}")

            # Check for license.txt
            license_url = f"{self.target_url}/license.txt"
            license_response = requests.get(license_url, headers=self.headers, timeout=5)

            if license_response.status_code == 200:
                # Check if it's a WordPress license
                if 'WordPress' in license_response.text:
                    self.results['exposed_files']['license'] = {
                        'url': license_url
                    }

                    # Add as improvement
                    self.results['improvements'].append({
                        'type': 'low',
                        'description': 'Arquivo license.txt acessível',
                        'recommendation': 'Remova ou bloqueie o acesso ao arquivo license.txt para reduzir a divulgação de informações'
                    })

                    print(f"{Fore.YELLOW}[!] Melhoria: license.txt acessível{Style.RESET_ALL}")

            if 'readme' not in self.results['exposed_files'] and 'license' not in self.results['exposed_files']:
                print(f"{Fore.GREEN}[+] Arquivos readme.html e license.txt não acessíveis{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar readme.html e license.txt: {str(e)}{Style.RESET_ALL}")

    def _check_security_headers(self):
        """Identify missing HTTP security headers"""
        try:
            response = requests.get(self.target_url, headers=self.headers, timeout=10)

            # Important security headers to check
            security_headers = {
                'Strict-Transport-Security': {
                    'description': 'HTTP Strict Transport Security (HSTS)',
                    'recommendation': 'Implemente o cabeçalho HSTS para garantir conexões HTTPS',
                    'type': 'medium'
                },
                'Content-Security-Policy': {
                    'description': 'Content Security Policy (CSP)',
                    'recommendation': 'Implemente uma política CSP para prevenir ataques XSS',
                    'type': 'medium'
                },
                'X-Frame-Options': {
                    'description': 'X-Frame-Options',
                    'recommendation': 'Adicione o cabeçalho X-Frame-Options para prevenir clickjacking',
                    'type': 'medium'
                },
                'X-Content-Type-Options': {
                    'description': 'X-Content-Type-Options',
                    'recommendation': 'Adicione o cabeçalho X-Content-Type-Options para prevenir MIME-sniffing',
                    'type': 'low'
                },
                'Referrer-Policy': {
                    'description': 'Referrer-Policy',
                    'recommendation': 'Adicione uma política de referência para controlar informações de referência',
                    'type': 'low'
                },
                'Permissions-Policy': {
                    'description': 'Permissions-Policy (Feature-Policy)',
                    'recommendation': 'Implemente uma política de permissões para controlar recursos do navegador',
                    'type': 'low'
                },
                'X-XSS-Protection': {
                    'description': 'X-XSS-Protection',
                    'recommendation': 'Adicione o cabeçalho X-XSS-Protection para proteção adicional contra XSS',
                    'type': 'low'
                }
            }

            # Check which headers are missing
            missing_headers = []
            present_headers = []

            for header, info in security_headers.items():
                if header in response.headers:
                    present_headers.append({
                        'name': header,
                        'value': response.headers[header]
                    })
                else:
                    missing_headers.append({
                        'name': header,
                        'description': info['description'],
                        'recommendation': info['recommendation'],
                        'type': info['type']
                    })

                    # Add to improvements
                    self.results['improvements'].append({
                        'type': info['type'],
                        'description': f'Cabeçalho de segurança ausente: {info["description"]}',
                        'recommendation': info['recommendation']
                    })

                    print(f"{Fore.YELLOW}[!] Melhoria: Cabeçalho de segurança ausente: {info['description']}{Style.RESET_ALL}")

            # Store results
            self.results['security_headers'] = {
                'missing': missing_headers,
                'present': present_headers
            }

            if not missing_headers:
                print(f"{Fore.GREEN}[+] Todos os cabeçalhos de segurança importantes estão presentes{Style.RESET_ALL}")

            # Check for insecure headers
            if 'Server' in response.headers:
                server_header = response.headers['Server']
                if server_header and len(server_header) > 0 and not server_header.lower() == 'apache' and not server_header.lower() == 'nginx':
                    self.results['improvements'].append({
                        'type': 'low',
                        'description': f'Cabeçalho Server expõe informações detalhadas: {server_header}',
                        'recommendation': 'Configure seu servidor web para ocultar ou minimizar informações no cabeçalho Server'
                    })
                    print(f"{Fore.YELLOW}[!] Melhoria: Cabeçalho Server expõe informações: {server_header}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar cabeçalhos de segurança: {str(e)}{Style.RESET_ALL}")

    def _check_php_execution(self):
        """Detect if PHP execution is allowed in uploads directory"""
        try:
            # Generate a random filename to avoid detection
            import random
            import string
            random_name = ''.join(random.choice(string.ascii_lowercase) for i in range(8))

            # Create a PHP file with a harmless payload that returns a specific string
            php_payload = f"""<?php 
            // This is a test file to check if PHP execution is allowed
            echo 'WP_SCAN_PHP_TEST_{random_name}'; 
            ?>"""

            # Try to upload the file with different extensions that might bypass restrictions
            test_extensions = [
                '.php',
                '.php.jpg',
                '.php.png',
                '.php.gif',
                '.php.txt',
                '.php5',
                '.phtml',
                '.php.unknown',
                '.php7',
                '.phps'
            ]

            uploads_paths = [
                '/wp-content/uploads/',
                '/wp-content/uploads/2023/',
                '/wp-content/uploads/2022/',
                '/wp-content/uploads/2021/',
                '/uploads/'
            ]

            php_execution_detected = False

            # First check if uploads directory is accessible and writable
            # This is just a passive check, we don't actually upload files
            for upload_path in uploads_paths:
                try:
                    # Check if directory exists and is listable
                    dir_url = f"{self.target_url}{upload_path}"
                    response = requests.get(dir_url, headers=self.headers, timeout=5)

                    if response.status_code == 200:
                        # Directory exists, now check for PHP files
                        for ext in test_extensions:
                            # We're not actually uploading, just checking if PHP files exist
                            test_url = f"{dir_url}test{ext}"
                            test_response = requests.head(test_url, headers=self.headers, timeout=5)

                            # If we find a PHP file in uploads, it might indicate PHP execution is allowed
                            if test_response.status_code == 200:
                                php_execution_detected = True
                                self.results['vulnerabilities'].append({
                                    'type': 'php_execution',
                                    'description': f'Possível execução de PHP no diretório de uploads detectada ({upload_path})',
                                    'recommendation': 'Configure seu servidor web para impedir a execução de PHP no diretório de uploads'
                                })
                                print(f"{Fore.RED}[!] Vulnerabilidade: Possível execução de PHP no diretório de uploads detectada ({upload_path}){Style.RESET_ALL}")
                                break
                except Exception as e:
                    # Skip if directory can't be accessed
                    pass

            if not php_execution_detected:
                # Check for .htaccess in uploads directory that might prevent PHP execution
                for upload_path in uploads_paths:
                    try:
                        htaccess_url = f"{self.target_url}{upload_path}.htaccess"
                        response = requests.head(htaccess_url, headers=self.headers, timeout=5)

                        if response.status_code == 200:
                            print(f"{Fore.GREEN}[+] Arquivo .htaccess encontrado no diretório de uploads, pode estar bloqueando execução de PHP{Style.RESET_ALL}")
                            break
                    except Exception as e:
                        # Skip if .htaccess can't be accessed
                        pass

                print(f"{Fore.GREEN}[+] Nenhuma evidência de execução de PHP no diretório de uploads detectada{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar execução de PHP: {str(e)}{Style.RESET_ALL}")

    def _check_login_protection(self):
        """Verify if the login page has 2FA or CAPTCHA protection"""
        try:
            login_url = f"{self.target_url}/wp-login.php"
            response = requests.get(login_url, headers=self.headers, timeout=10)

            if response.status_code == 200:
                # Check for common 2FA and CAPTCHA plugins/solutions
                protection_found = False

                # Check for common 2FA plugins
                two_fa_indicators = [
                    'two-factor',
                    'two factor',
                    '2fa',
                    'two step',
                    'two-step',
                    'google authenticator',
                    'authy',
                    'duo security',
                    'wordfence',
                    'ithemes security',
                    'all in one wp security',
                    'miniOrange',
                    'wp 2fa',
                    'authentication code',
                    'código de autenticação',
                    'código de verificação',
                    'verification code'
                ]

                # Check for CAPTCHA solutions
                captcha_indicators = [
                    'captcha',
                    'recaptcha',
                    'hcaptcha',
                    'cloudflare turnstile',
                    'are you a human',
                    'prove you\'re human',
                    'prove you are human',
                    'não sou um robô',
                    'i\'m not a robot',
                    'i am not a robot'
                ]

                # Check for login attempt limiting
                limit_indicators = [
                    'limit login attempts',
                    'login lockdown',
                    'login security',
                    'brute force protection',
                    'proteção contra força bruta',
                    'tentativas de login',
                    'login attempts'
                ]

                # Combine all indicators
                all_indicators = two_fa_indicators + captcha_indicators + limit_indicators

                # Check if any indicator is found in the login page
                for indicator in all_indicators:
                    if indicator.lower() in response.text.lower():
                        protection_type = 'Desconhecido'
                        if indicator in two_fa_indicators:
                            protection_type = '2FA'
                        elif indicator in captcha_indicators:
                            protection_type = 'CAPTCHA'
                        elif indicator in limit_indicators:
                            protection_type = 'Limitação de tentativas'

                        self.results['additional_info']['login_protection'] = {
                            'detected': True,
                            'type': protection_type,
                            'indicator': indicator
                        }

                        print(f"{Fore.GREEN}[+] Proteção de login detectada: {protection_type} ({indicator}){Style.RESET_ALL}")
                        protection_found = True
                        break

                # Check for login protection plugins by looking at the page source
                protection_plugins = {
                    'wordfence': 'Wordfence',
                    'ithemes-security': 'iThemes Security',
                    'all-in-one-wp-security': 'All In One WP Security',
                    'better-wp-security': 'Better WP Security',
                    'sucuri': 'Sucuri Security',
                    'wp-simple-firewall': 'Shield Security',
                    'jetpack': 'Jetpack',
                    'google-authenticator': 'Google Authenticator',
                    'two-factor': 'Two Factor',
                    'wp-2fa': 'WP 2FA',
                    'miniorange': 'miniOrange',
                    'duo-wordpress': 'Duo Security',
                    'limit-login-attempts': 'Limit Login Attempts',
                    'login-lockdown': 'Login Lockdown'
                }

                for plugin_id, plugin_name in protection_plugins.items():
                    if plugin_id in response.text:
                        self.results['additional_info']['login_protection'] = {
                            'detected': True,
                            'type': 'Plugin',
                            'name': plugin_name
                        }

                        print(f"{Fore.GREEN}[+] Plugin de proteção de login detectado: {plugin_name}{Style.RESET_ALL}")
                        protection_found = True
                        break

                if not protection_found:
                    self.results['additional_info']['login_protection'] = {
                        'detected': False
                    }

                    self.results['improvements'].append({
                        'type': 'medium',
                        'description': 'Nenhuma proteção de login (2FA/CAPTCHA) detectada',
                        'recommendation': 'Implemente autenticação de dois fatores (2FA) ou CAPTCHA na página de login para aumentar a segurança'
                    })

                    print(f"{Fore.YELLOW}[!] Melhoria: Nenhuma proteção de login (2FA/CAPTCHA) detectada{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Não foi possível acessar a página de login para verificar proteções{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar proteção de login: {str(e)}{Style.RESET_ALL}")

    def _check_auto_updates(self):
        """Check if automatic updates are enabled"""
        try:
            # We can't directly check wp-config.php, but we can look for indicators
            # in the HTML source of the site or in the WordPress API

            # First, check if the site has a /wp-json/wp/v2/settings endpoint
            # which might reveal auto-update settings
            settings_url = f"{self.target_url}/wp-json/wp/v2/settings"
            try:
                settings_response = requests.get(settings_url, headers=self.headers, timeout=5)
                if settings_response.status_code == 200:
                    settings_data = settings_response.json()

                    # Check if auto_update_core is in the settings
                    if 'auto_update_core' in settings_data:
                        auto_update_core = settings_data['auto_update_core']
                        self.results['additional_info']['auto_updates'] = {
                            'core': auto_update_core
                        }

                        if auto_update_core:
                            print(f"{Fore.GREEN}[+] Atualizações automáticas do WordPress estão habilitadas{Style.RESET_ALL}")
                        else:
                            self.results['improvements'].append({
                                'type': 'medium',
                                'description': 'Atualizações automáticas do WordPress estão desabilitadas',
                                'recommendation': 'Habilite as atualizações automáticas para manter o WordPress atualizado com correções de segurança'
                            })
                            print(f"{Fore.YELLOW}[!] Melhoria: Atualizações automáticas do WordPress estão desabilitadas{Style.RESET_ALL}")
            except:
                pass

            # Check for auto-update plugins
            auto_update_plugins = [
                'companion-auto-update',
                'auto-updater',
                'wp-auto-updater',
                'advanced-automatic-updates',
                'easy-updates-manager'
            ]

            # Check the main page source for indicators of auto-update plugins
            response = requests.get(self.target_url, headers=self.headers, timeout=10)

            auto_update_plugin_found = False
            for plugin in auto_update_plugins:
                if plugin in response.text:
                    self.results['additional_info']['auto_updates'] = {
                        'plugin_detected': True,
                        'plugin_name': plugin
                    }
                    print(f"{Fore.GREEN}[+] Plugin de atualizações automáticas detectado: {plugin}{Style.RESET_ALL}")
                    auto_update_plugin_found = True
                    break

            # Check for common auto-update indicators in the HTML
            auto_update_indicators = [
                'automatic updates',
                'auto updates',
                'atualizações automáticas',
                'auto-update',
                'autoupdate'
            ]

            for indicator in auto_update_indicators:
                if indicator.lower() in response.text.lower():
                    if 'additional_info' not in self.results or 'auto_updates' not in self.results['additional_info']:
                        self.results['additional_info']['auto_updates'] = {
                            'indicator_detected': True,
                            'indicator': indicator
                        }
                    print(f"{Fore.GREEN}[+] Indicador de atualizações automáticas detectado: {indicator}{Style.RESET_ALL}")
                    auto_update_plugin_found = True
                    break

            # If we couldn't determine auto-update status, add an improvement suggestion
            if not auto_update_plugin_found and ('additional_info' not in self.results or 'auto_updates' not in self.results['additional_info']):
                self.results['additional_info']['auto_updates'] = {
                    'detected': False
                }

                self.results['improvements'].append({
                    'type': 'medium',
                    'description': 'Status de atualizações automáticas não detectado',
                    'recommendation': 'Habilite as atualizações automáticas para manter o WordPress, plugins e temas atualizados com correções de segurança'
                })

                print(f"{Fore.YELLOW}[!] Melhoria: Status de atualizações automáticas não detectado{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar atualizações automáticas: {str(e)}{Style.RESET_ALL}")

    def _check_nulled_plugins_themes(self):
        """Detect if the site uses nulled (pirated) plugins or themes"""
        try:
            # Get the main page source
            response = requests.get(self.target_url, headers=self.headers, timeout=10)

            # Common indicators of nulled plugins/themes
            nulled_indicators = [
                # Common text in nulled plugins/themes
                'nulled',
                'cracked',
                'wplocker',
                'codecanyon nulled',
                'themeforest nulled',
                'gplvault',
                'gpl-licensed',
                'gplking',
                'gplsuperior',
                'gplfox',
                'gplpremium',
                'gplclub',
                'gplnull',
                'gplvip',
                'gplplugins',
                'gplthemes',
                'gpldownload',
                'gplstore',
                'gplvault',
                'gplpro',
                'gplbazaar',
                'gplfreethemes',
                'gplfreeplugins',
                'gplplugins',
                'gplthemes',
                'gplvault',
                'gplking',
                'gplsuperior',
                'gplfox',
                'gplpremium',
                'gplclub',
                'gplnull',
                'gplvip',

                # Common domains that host nulled content
                'wplocker.com',
                'codecanyon.net/nulled',
                'themeforest.net/nulled',
                'nulledplugins',
                'nulledthemes',
                'nulledscripts',
                'nulledhack',
                'nulledcodes',
                'nulledwp',
                'wpnulled',
                'themesnulled',
                'pluginsnulled',
                'nulledtheme',
                'nulledplugin',
                'crackedthemes',
                'crackedplugins',
                'freethemesdl',
                'downloadfreethemes',
                'downloadfreeplugins',
                'downloadnulled',
                'downloadcracked',
                'downloadpirated',
                'piratedthemes',
                'piratedplugins',
                'warez',
                'serialkey',
                'keygen',
                'activation key generator',
                'license key generator',
                'nulledcore',
                'wpfreedownload',
                'freewpdownload'
            ]

            # Check for nulled indicators in the page source
            nulled_found = False
            for indicator in nulled_indicators:
                if indicator.lower() in response.text.lower():
                    self.results['vulnerabilities'].append({
                        'type': 'nulled_software',
                        'description': f'Possível uso de software pirata/nulled detectado (indicador: {indicator})',
                        'recommendation': 'Utilize apenas plugins e temas de fontes oficiais para evitar malware e vulnerabilidades de segurança'
                    })

                    print(f"{Fore.RED}[!] Vulnerabilidade: Possível uso de software pirata/nulled detectado (indicador: {indicator}){Style.RESET_ALL}")
                    nulled_found = True
                    break

            # Check for suspicious code patterns often found in nulled plugins/themes
            suspicious_patterns = [
                'base64_decode',
                'eval(',
                'gzinflate(',
                'str_rot13(',
                'eval(base64_decode',
                'eval(gzinflate',
                'eval(str_rot13',
                'preg_replace(\'/\\.\*/e',
                'create_function(',
                'passthru(',
                'shell_exec(',
                'system(',
                'proc_open(',
                'popen(',
                'curl_exec(',
                'curl_multi_exec(',
                'parse_ini_file(',
                'show_source(',
                'eval(stripslashes',
                'assert(',
                'preg_replace(\'/(.*)\/e'
            ]

            # Check for suspicious code patterns in the page source
            for pattern in suspicious_patterns:
                if pattern in response.text:
                    if not nulled_found:  # Only add if we haven't already found a nulled indicator
                        self.results['vulnerabilities'].append({
                            'type': 'suspicious_code',
                            'description': f'Código suspeito detectado (padrão: {pattern}), possivelmente de plugin/tema pirata',
                            'recommendation': 'Verifique seus plugins e temas em busca de código malicioso e utilize apenas software de fontes oficiais'
                        })

                        print(f"{Fore.RED}[!] Vulnerabilidade: Código suspeito detectado (padrão: {pattern}), possivelmente de plugin/tema pirata{Style.RESET_ALL}")
                        nulled_found = True
                        break

            # Check for common obfuscated code patterns
            obfuscated_patterns = [
                '\\x',  # Hex encoding
                '\\u00',  # Unicode encoding
                '\\\\',  # Escaped backslashes
                '\\\\x',  # Escaped hex
                '\\\\u00'  # Escaped unicode
            ]

            # Count occurrences of obfuscated patterns
            obfuscation_count = 0
            for pattern in obfuscated_patterns:
                obfuscation_count += response.text.count(pattern)

            # If there's a high number of obfuscated patterns, it might be suspicious
            if obfuscation_count > 100 and not nulled_found:  # Arbitrary threshold
                self.results['vulnerabilities'].append({
                    'type': 'obfuscated_code',
                    'description': 'Código ofuscado detectado em grande quantidade, possivelmente de plugin/tema pirata',
                    'recommendation': 'Verifique seus plugins e temas em busca de código malicioso e utilize apenas software de fontes oficiais'
                })

                print(f"{Fore.RED}[!] Vulnerabilidade: Código ofuscado detectado em grande quantidade, possivelmente de plugin/tema pirata{Style.RESET_ALL}")
                nulled_found = True

            if not nulled_found:
                print(f"{Fore.GREEN}[+] Nenhum indicador de plugins/temas piratas (nulled) detectado{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao verificar plugins/temas piratas: {str(e)}{Style.RESET_ALL}")

    def _check_sitemap_robots(self):
        """Analyze sitemap.xml and robots.txt for potential security issues"""
        try:
            # Check robots.txt
            robots_url = f"{self.target_url}/robots.txt"
            robots_response = requests.get(robots_url, headers=self.headers, timeout=5)

            if robots_response.status_code == 200:
                robots_content = robots_response.text
                self.results['sitemap_robots']['robots_txt'] = {
                    'exists': True,
                    'content': robots_content
                }

                print(f"{Fore.GREEN}[+] Arquivo robots.txt encontrado{Style.RESET_ALL}")

                # Check for sensitive directories in robots.txt
                sensitive_dirs = [
                    '/wp-admin',
                    '/wp-includes',
                    '/wp-content',
                    '/wp-content/uploads',
                    '/wp-content/plugins',
                    '/wp-content/themes',
                    '/wp-json',
                    '/admin',
                    '/login',
                    '/backup',
                    '/backups',
                    '/wp-config',
                    '/.git',
                    '/.svn',
                    '/private'
                ]

                exposed_dirs = []
                for directory in sensitive_dirs:
                    # Check if directory is explicitly allowed
                    if f"Allow: {directory}" in robots_content:
                        exposed_dirs.append(directory)

                if exposed_dirs:
                    self.results['sitemap_robots']['exposed_dirs'] = exposed_dirs

                    self.results['improvements'].append({
                        'type': 'medium',
                        'description': f'Diretórios sensíveis expostos no robots.txt: {", ".join(exposed_dirs)}',
                        'recommendation': 'Remova diretórios sensíveis do robots.txt ou bloqueie o acesso a eles'
                    })

                    print(f"{Fore.YELLOW}[!] Melhoria: Diretórios sensíveis expostos no robots.txt: {', '.join(exposed_dirs)}{Style.RESET_ALL}")

                # Extract sitemap URLs from robots.txt
                sitemap_urls = []
                for line in robots_content.splitlines():
                    if line.lower().startswith('sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        sitemap_urls.append(sitemap_url)

                if sitemap_urls:
                    self.results['sitemap_robots']['sitemaps_from_robots'] = sitemap_urls
                    print(f"{Fore.GREEN}[+] Sitemaps encontrados no robots.txt: {len(sitemap_urls)}{Style.RESET_ALL}")
            else:
                self.results['sitemap_robots']['robots_txt'] = {
                    'exists': False
                }
                print(f"{Fore.YELLOW}[!] Arquivo robots.txt não encontrado{Style.RESET_ALL}")

            # Check common sitemap locations
            sitemap_locations = [
                '/sitemap.xml',
                '/sitemap_index.xml',
                '/sitemap-index.xml',
                '/wp-sitemap.xml',
                '/post-sitemap.xml',
                '/page-sitemap.xml',
                '/category-sitemap.xml'
            ]

            found_sitemaps = []
            for sitemap_path in sitemap_locations:
                try:
                    sitemap_url = f"{self.target_url}{sitemap_path}"
                    sitemap_response = requests.get(sitemap_url, headers=self.headers, timeout=5)

                    if sitemap_response.status_code == 200 and ('<?xml' in sitemap_response.text or '<urlset' in sitemap_response.text or '<sitemapindex' in sitemap_response.text):
                        found_sitemaps.append({
                            'url': sitemap_url,
                            'size': len(sitemap_response.text)
                        })
                        print(f"{Fore.GREEN}[+] Sitemap encontrado: {sitemap_path}{Style.RESET_ALL}")

                        # Check for sensitive URLs in sitemap
                        sensitive_patterns = [
                            '/wp-admin',
                            '/wp-login',
                            '/admin',
                            '/login',
                            '/wp-content/uploads/private',
                            '/wp-content/uploads/confidential',
                            '/wp-content/uploads/users',
                            '/wp-content/uploads/backup',
                            '/backup',
                            '/backups',
                            '/wp-json',
                            '/api',
                            '/private',
                            '/confidential',
                            '/internal'
                        ]

                        exposed_urls = []
                        for pattern in sensitive_patterns:
                            if pattern in sitemap_response.text:
                                exposed_urls.append(pattern)

                        if exposed_urls:
                            if 'exposed_urls' not in self.results['sitemap_robots']:
                                self.results['sitemap_robots']['exposed_urls'] = []

                            self.results['sitemap_robots']['exposed_urls'].extend(exposed_urls)

                            self.results['improvements'].append({
                                'type': 'medium',
                                'description': f'URLs sensíveis expostas no sitemap: {", ".join(exposed_urls)}',
                                'recommendation': 'Remova URLs sensíveis do sitemap para evitar exposição desnecessária'
                            })

                            print(f"{Fore.YELLOW}[!] Melhoria: URLs sensíveis expostas no sitemap: {', '.join(exposed_urls)}{Style.RESET_ALL}")
                except Exception as e:
                    # Skip if sitemap can't be accessed
                    pass

            if found_sitemaps:
                self.results['sitemap_robots']['sitemaps'] = found_sitemaps
            else:
                print(f"{Fore.YELLOW}[!] Nenhum sitemap encontrado{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao analisar sitemap.xml e robots.txt: {str(e)}{Style.RESET_ALL}")

    def _check_js_css_versions(self):
        """List and analyze JS and CSS files with version query strings"""
        try:
            # Get the main page source
            response = requests.get(self.target_url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all script and link tags
            scripts = soup.find_all('script', src=True)
            styles = soup.find_all('link', {'rel': 'stylesheet', 'href': True})

            # Combine all resources
            resources = []

            # Process scripts
            for script in scripts:
                src = script.get('src', '')
                if '?' in src and ('ver=' in src or 'version=' in src):
                    version = self._extract_version_from_url(src)
                    resources.append({
                        'type': 'js',
                        'url': src,
                        'version': version
                    })

            # Process styles
            for style in styles:
                href = style.get('href', '')
                if '?' in href and ('ver=' in href or 'version=' in href):
                    version = self._extract_version_from_url(href)
                    resources.append({
                        'type': 'css',
                        'url': href,
                        'version': version
                    })

            # Store results
            if resources:
                self.results['js_css_versions'] = resources
                print(f"{Fore.GREEN}[+] Encontrados {len(resources)} arquivos JS/CSS com strings de versão{Style.RESET_ALL}")

                # Check for outdated WordPress core JS/CSS files
                wp_core_files = []
                for resource in resources:
                    # Check if it's a WordPress core file
                    if '/wp-includes/' in resource['url'] or '/wp-admin/' in resource['url']:
                        if resource['version'] and resource['version'] != 'unknown':
                            wp_core_files.append(resource)

                if wp_core_files and self.results['wordpress_version']:
                    # Check if any core file has a different version than the WordPress version
                    wp_version = self.results['wordpress_version']
                    outdated_files = []

                    for file in wp_core_files:
                        if file['version'] != wp_version:
                            # Only consider it outdated if the version is actually lower
                            try:
                                if self._compare_versions(file['version'], wp_version) < 0:
                                    outdated_files.append(file)
                            except:
                                # If we can't compare versions, just skip
                                pass

                    if outdated_files:
                        self.results['improvements'].append({
                            'type': 'medium',
                            'description': f'Arquivos core do WordPress desatualizados detectados: {len(outdated_files)} arquivos',
                            'recommendation': 'Atualize o WordPress para a versão mais recente para garantir que todos os arquivos estejam atualizados'
                        })
                        print(f"{Fore.YELLOW}[!] Melhoria: Arquivos core do WordPress desatualizados detectados{Style.RESET_ALL}")

                # Check for potentially vulnerable plugin/theme versions
                plugin_theme_files = []
                for resource in resources:
                    # Check if it's a plugin or theme file
                    if '/wp-content/plugins/' in resource['url'] or '/wp-content/themes/' in resource['url']:
                        if resource['version'] and resource['version'] != 'unknown':
                            plugin_theme_files.append(resource)

                if plugin_theme_files:
                    # We can't know for sure if these are vulnerable without a database,
                    # but we can suggest keeping them updated
                    self.results['improvements'].append({
                        'type': 'low',
                        'description': f'Arquivos de plugins/temas com versões expostas: {len(plugin_theme_files)} arquivos',
                        'recommendation': 'Mantenha plugins e temas atualizados e considere ocultar as versões para reduzir a exposição de informações'
                    })
                    print(f"{Fore.YELLOW}[!] Melhoria: Arquivos de plugins/temas com versões expostas detectados{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Nenhum arquivo JS/CSS com string de versão encontrado{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao analisar versões de JS/CSS: {str(e)}{Style.RESET_ALL}")

    def _extract_version_from_url(self, url):
        """Extract version from URL query string"""
        try:
            if '?' not in url:
                return 'unknown'

            query_string = url.split('?', 1)[1]
            params = query_string.split('&')

            for param in params:
                if param.startswith('ver=') or param.startswith('version='):
                    version = param.split('=', 1)[1]
                    return version

            return 'unknown'
        except:
            return 'unknown'

    def _compare_versions(self, version1, version2):
        """Compare two version strings"""
        # Split versions into components
        v1_parts = version1.split('.')
        v2_parts = version2.split('.')

        # Pad with zeros to make them the same length
        while len(v1_parts) < len(v2_parts):
            v1_parts.append('0')
        while len(v2_parts) < len(v1_parts):
            v2_parts.append('0')

        # Compare each component
        for i in range(len(v1_parts)):
            try:
                v1 = int(v1_parts[i])
                v2 = int(v2_parts[i])
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1
            except ValueError:
                # If we can't convert to int, compare as strings
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1

        # If we get here, they're equal
        return 0

    def print_report(self):
        """Print a formatted report of the scan results"""
        print("\n" + "="*50)
        print(f"{Fore.CYAN}Relatório de Análise WordPress para {self.target_url}{Style.RESET_ALL}")
        print("="*50)

        # WordPress version
        if self.results['wordpress_version']:
            print(f"\n{Fore.CYAN}Versão do WordPress:{Style.RESET_ALL} {self.results['wordpress_version']}")
        else:
            print(f"\n{Fore.CYAN}Versão do WordPress:{Style.RESET_ALL} Desconhecida")

        # Theme information
        if self.results['theme']:
            print(f"\n{Fore.CYAN}Tema:{Style.RESET_ALL} {self.results['theme']['name']}")
        else:
            print(f"\n{Fore.CYAN}Tema:{Style.RESET_ALL} Não detectado")

        # Plugins
        print(f"\n{Fore.CYAN}Plugins:{Style.RESET_ALL}")
        if self.results['plugins']:
            for plugin in self.results['plugins']:
                status = "Ativo" if plugin['status'] == "Active" else "Inativo" if plugin['status'] == "Inactive" else "Desconhecido"
                print(f"  - {plugin['name']} ({status})")
        else:
            print("  Nenhum plugin detectado")

        # Vulnerabilities
        print(f"\n{Fore.CYAN}Vulnerabilidades:{Style.RESET_ALL}")
        if self.results['vulnerabilities']:
            for vuln in self.results['vulnerabilities']:
                print(f"  - {Fore.RED}{vuln['description']}{Style.RESET_ALL}")
                print(f"    Recomendação: {vuln['recommendation']}")
        else:
            print("  Nenhuma vulnerabilidade óbvia detectada")

        # Improvements
        print(f"\n{Fore.CYAN}Melhorias Sugeridas:{Style.RESET_ALL}")
        if self.results['improvements']:
            for imp in self.results['improvements']:
                if imp['type'] == 'critical':
                    print(f"  - {Fore.RED}[CRÍTICO] {imp['description']}{Style.RESET_ALL}")
                elif imp['type'] == 'medium':
                    print(f"  - {Fore.YELLOW}[MÉDIO] {imp['description']}{Style.RESET_ALL}")
                else:
                    print(f"  - {Fore.GREEN}[BAIXO] {imp['description']}{Style.RESET_ALL}")
                print(f"    Recomendação: {imp['recommendation']}")
        else:
            print("  Nenhuma melhoria óbvia necessária")

        # Hosting information
        print(f"\n{Fore.CYAN}Informações de Hospedagem:{Style.RESET_ALL}")
        if isinstance(self.results['hosting'], dict) and 'error' not in self.results['hosting']:
            print(f"  Endereço IP: {self.results['hosting'].get('ip', 'Desconhecido')}")
            print(f"  Servidor: {self.results['hosting'].get('server', 'Desconhecido')}")
            print(f"  Registrador: {self.results['hosting'].get('registrar', 'Desconhecido')}")
            print(f"  Data de Criação: {self.results['hosting'].get('creation_date', 'Desconhecida')}")
            print(f"  Data de Expiração: {self.results['hosting'].get('expiration_date', 'Desconhecida')}")
        else:
            print("  Informações de hospedagem não disponíveis")

        # DNS Zones
        print(f"\n{Fore.CYAN}Zonas DNS:{Style.RESET_ALL}")
        if self.results['dns_zones']:
            for zone in self.results['dns_zones']:
                print(f"  Registros {zone['type']}:")
                for record in zone['records']:
                    print(f"    - {record}")
        else:
            print("  Informações DNS não disponíveis")

        # WAF Information
        if 'waf' in self.results['additional_info']:
            print(f"\n{Fore.CYAN}Firewall de Aplicação Web (WAF):{Style.RESET_ALL}")
            if self.results['additional_info']['waf'].get('detected', False):
                print(f"  Detectado: {self.results['additional_info']['waf'].get('name', 'Desconhecido')}")
            else:
                print("  Nenhum WAF detectado")

        # SSL Information
        if 'ssl' in self.results['additional_info']:
            print(f"\n{Fore.CYAN}Segurança SSL/TLS:{Style.RESET_ALL}")
            if self.results['additional_info']['ssl'].get('enabled', False):
                print(f"  SSL Ativado: Sim")
                print(f"  HSTS Implementado: {'Sim' if self.results['additional_info']['ssl'].get('hsts', False) else 'Não'}")
            else:
                print("  SSL Ativado: Não")

        # User Information
        if 'users' in self.results['additional_info'] and self.results['additional_info']['users']:
            print(f"\n{Fore.CYAN}Usuários Detectados:{Style.RESET_ALL}")
            for user in self.results['additional_info']['users'][:5]:  # Show only first 5 users
                print(f"  - Nome: {user.get('name', 'Desconhecido')}, ID: {user.get('id', 'Desconhecido')}")
            if len(self.results['additional_info']['users']) > 5:
                print(f"  ... e mais {len(self.results['additional_info']['users']) - 5} usuários")

        # Login Protection
        if 'login_protection' in self.results['additional_info']:
            print(f"\n{Fore.CYAN}Proteção de Login:{Style.RESET_ALL}")
            if self.results['additional_info']['login_protection'].get('detected', False):
                protection_type = self.results['additional_info']['login_protection'].get('type', 'Desconhecido')
                if 'name' in self.results['additional_info']['login_protection']:
                    print(f"  Plugin de proteção detectado: {self.results['additional_info']['login_protection']['name']}")
                elif 'indicator' in self.results['additional_info']['login_protection']:
                    print(f"  Tipo de proteção: {protection_type}")
                    print(f"  Indicador: {self.results['additional_info']['login_protection']['indicator']}")
                else:
                    print(f"  Tipo de proteção: {protection_type}")
            else:
                print("  Nenhuma proteção de login detectada")

        # Auto Updates
        if 'auto_updates' in self.results['additional_info']:
            print(f"\n{Fore.CYAN}Atualizações Automáticas:{Style.RESET_ALL}")
            if 'core' in self.results['additional_info']['auto_updates']:
                print(f"  WordPress Core: {'Habilitado' if self.results['additional_info']['auto_updates']['core'] else 'Desabilitado'}")
            elif 'plugin_detected' in self.results['additional_info']['auto_updates']:
                print(f"  Plugin de atualização automática: {self.results['additional_info']['auto_updates']['plugin_name']}")
            elif 'indicator_detected' in self.results['additional_info']['auto_updates']:
                print(f"  Indicador de atualizações automáticas: {self.results['additional_info']['auto_updates']['indicator']}")
            else:
                print("  Status desconhecido")

        # Listable Directories
        if self.results['listable_directories']:
            print(f"\n{Fore.CYAN}Diretórios com Listagem Habilitada:{Style.RESET_ALL}")
            for directory in self.results['listable_directories']:
                print(f"  - {directory['url']}")

        # Sensitive Files
        if self.results['sensitive_files'] or self.results['wp_config_backups']:
            print(f"\n{Fore.CYAN}Arquivos Sensíveis Expostos:{Style.RESET_ALL}")

            if self.results['wp_config_backups']:
                print(f"  {Fore.RED}Backups de wp-config.php:{Style.RESET_ALL}")
                for file in self.results['wp_config_backups']:
                    print(f"    - {file}")

            for file_type, files in self.results['sensitive_files'].items():
                if files:
                    print(f"  {Fore.RED}Arquivos {file_type}:{Style.RESET_ALL}")
                    for file in files:
                        print(f"    - {file}")

        # Security Headers
        if 'security_headers' in self.results:
            print(f"\n{Fore.CYAN}Cabeçalhos de Segurança HTTP:{Style.RESET_ALL}")
            if 'missing' in self.results['security_headers'] and self.results['security_headers']['missing']:
                print(f"  {Fore.YELLOW}Cabeçalhos ausentes:{Style.RESET_ALL}")
                for header in self.results['security_headers']['missing']:
                    print(f"    - {header['name']}: {header['description']}")

            if 'present' in self.results['security_headers'] and self.results['security_headers']['present']:
                print(f"  {Fore.GREEN}Cabeçalhos presentes:{Style.RESET_ALL}")
                for header in self.results['security_headers']['present']:
                    print(f"    - {header['name']}")

        # Sitemap and Robots.txt
        if 'sitemap_robots' in self.results:
            print(f"\n{Fore.CYAN}Sitemap e Robots.txt:{Style.RESET_ALL}")

            if 'robots_txt' in self.results['sitemap_robots']:
                if self.results['sitemap_robots']['robots_txt'].get('exists', False):
                    print(f"  {Fore.GREEN}Robots.txt encontrado{Style.RESET_ALL}")
                    if 'exposed_dirs' in self.results['sitemap_robots']:
                        print(f"  {Fore.YELLOW}Diretórios sensíveis expostos no robots.txt:{Style.RESET_ALL}")
                        for dir in self.results['sitemap_robots']['exposed_dirs']:
                            print(f"    - {dir}")
                else:
                    print(f"  {Fore.YELLOW}Robots.txt não encontrado{Style.RESET_ALL}")

            if 'sitemaps' in self.results['sitemap_robots']:
                print(f"  {Fore.GREEN}Sitemaps encontrados:{Style.RESET_ALL}")
                for sitemap in self.results['sitemap_robots']['sitemaps']:
                    print(f"    - {sitemap['url']}")

                if 'exposed_urls' in self.results['sitemap_robots']:
                    print(f"  {Fore.YELLOW}URLs sensíveis expostas no sitemap:{Style.RESET_ALL}")
                    for url in self.results['sitemap_robots']['exposed_urls']:
                        print(f"    - {url}")

        # JS/CSS Versions
        if self.results['js_css_versions']:
            print(f"\n{Fore.CYAN}Arquivos JS/CSS com Versões:{Style.RESET_ALL}")
            print(f"  Total de arquivos com versão: {len(self.results['js_css_versions'])}")

            # Group by type
            js_files = [f for f in self.results['js_css_versions'] if f['type'] == 'js']
            css_files = [f for f in self.results['js_css_versions'] if f['type'] == 'css']

            if js_files:
                print(f"  {Fore.YELLOW}Arquivos JavaScript com versão: {len(js_files)}{Style.RESET_ALL}")
                # Show only first 3 as example
                for file in js_files[:3]:
                    print(f"    - {file['url']} (versão: {file['version']})")
                if len(js_files) > 3:
                    print(f"    ... e mais {len(js_files) - 3} arquivos")

            if css_files:
                print(f"  {Fore.YELLOW}Arquivos CSS com versão: {len(css_files)}{Style.RESET_ALL}")
                # Show only first 3 as example
                for file in css_files[:3]:
                    print(f"    - {file['url']} (versão: {file['version']})")
                if len(css_files) > 3:
                    print(f"    ... e mais {len(css_files) - 3} arquivos")

        print("\n" + "="*50)

    def get_json_report(self):
        """Return the results as a JSON string"""
        return json.dumps(self.results, indent=2)


def interactive_mode():
    """Run the scanner in interactive mode"""
    print(f"{Fore.CYAN}Scanner WordPress - Modo Interativo{Style.RESET_ALL}")
    print("="*50)

    while True:
        target_url = input("\nDigite a URL do site WordPress (ou 'sair' para encerrar): ")

        if target_url.lower() in ['sair', 'exit']:
            print("Encerrando...")
            break

        scanner = WordPressScanner(target_url)
        scanner.scan()
        scanner.print_report()

        save_option = input("\nSalvar resultados em arquivo JSON? (s/n): ")
        if save_option.lower() in ['s', 'y', 'sim', 'yes']:
            filename = input("Digite o nome do arquivo (padrão: wp_scan_results.json): ") or "wp_scan_results.json"
            with open(filename, 'w') as f:
                f.write(scanner.get_json_report())
            print(f"Resultados salvos em {filename}")


def main():
    parser = argparse.ArgumentParser(description='Scanner WordPress - Ferramenta de análise de sites WordPress')
    parser.add_argument('-u', '--url', help='URL do site WordPress alvo')
    parser.add_argument('-o', '--output', help='Arquivo JSON de saída')
    parser.add_argument('-i', '--interactive', action='store_true', help='Executar em modo interativo')

    args = parser.parse_args()

    if args.interactive or len(sys.argv) == 1:
        interactive_mode()
    elif args.url:
        scanner = WordPressScanner(args.url)
        scanner.scan()
        scanner.print_report()

        if args.output:
            with open(args.output, 'w') as f:
                f.write(scanner.get_json_report())
            print(f"Resultados salvos em {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
