import json
import datetime
import requests
import ssl
import socket
from whois import whois
from ipwhois import IPWhois
from tld import get_tld
from html2text import html2text
from threading import Thread
from bson import json_util
from .thread_with_return import ThreadWithReturn
from .ssl_check import get_certificate, get_issuer, get_common_name, get_alt_names


class Scoring:

    def __init__(self, url):
        self.url_data = {}
        self.tld_data = {}

        self._url = url

        self._domain_age = 1
        self._tld = {}
        self._domain = ''
        self._hostname = ''
        self._main_page = ''

        self._has_robots = False
        self._sitemap_in_robots = False
        self._path_to_sitemap = ''
        self._has_sitemap = False
        self._number_of_pages = 0

        self._is_personal_owner = True
        self._indexed_pages = 0
        self._subject = "unsecured"
        self._issuer = "unsecured"
        self._valid_domain = False
        self._free_ssl = False
        self._self_signed_ssl = False
        self._no_ssl = False
        self._ns_servers = []
        self._own_ns_servers = False
        self._free_host = False
        self._free_tld = False
        self._legal_tld = False
        self._has_genetator = True
        self._is_accessible = False
        self._html = ''
        self._html_len = 0
        self._text = ''
        self._text_len = 0
        self._text_to_html_ratio = 0
        self._has_genetator = False
        self._use_stats = False

        self._ssl_info = None

        self._ip_addr = ''
        self._ip_info = {}
        self._asn = 0

    def start_analysis(self):
        thread_url = Thread(target=self._use_url_data, args=())
        thread_tld = Thread(target=self._use_tld_data, args=())
        thread_nav_data = Thread(target=self._check_navigation_data, args=())
        thread_ip = Thread(target=self._get_ip_info, args=())
        thread_secur = Thread(target=self._check_security, args=())
        thread_html = Thread(target=self._get_html, args=())

        thread_url.start()
        thread_tld.start()
        thread_tld.join()
        thread_nav_data.start()
        thread_html.start()
        thread_ip.start()
        thread_url.join()
        thread_html.join()

        thread_secur.start()
        thread_ip.join()
        thread_nav_data.join()
        thread_secur.join()

        del self.url_data
        del self.tld_data

    def _use_tld_data(self):
        self.tld_data = get_tld(self._url, as_object=True, fail_silently=True)
        self._tld =  self.tld_data.tld.replace(self.tld_data.domain, '')[1:]
        self._domain = self.tld_data.domain
        self._hostname = self.tld_data.tld
        self._main_page = "http://" + self._hostname

    def _use_url_data(self):
        self.url_data = whois(self._url)
        self._calc_domain_age()
        self._ns_servers = self.url_data.name_servers

    def _calc_domain_age(self):
        """ Calculate age of domain

        """
        if type(self.url_data.creation_date) is list:
            try:
                domain_age = (datetime.datetime.now() - self.url_data.creation_date[0]).days // 30
            except:
                print('Unknown', self.url_data.creation_date[0])
        else:
            if self.url_data.creation_date is None:
                domain_age = 1
            else:
                try:
                    domain_age = (datetime.datetime.now() - self.url_data.creation_date).days // 30
                except:
                    print('Unknown', self.url_data.creation_date)


        if domain_age < 1:
            domain_age = 1

        self._domain_age = domain_age

    def _get_ip_info(self):
        """ Get information about IP address from ipwhois

        """
        ip_addr = socket.gethostbyname(self._hostname)  # Detect IP address
        obj = IPWhois(ip_addr)
        results = obj.lookup_rdap(depth=1)

        # Get all keys with not null value
        info = {key: value for key, value in results.items() if value is not None}

        self._ip_addr = ip_addr
        self._ip_info = info
        self._asn = info['asn']

    def _check_navigation_data(self):
        """ Check main navigation data: has_robots, sitemap_in_robots, path_to_sitemap, has_sitemap, pages

        """
        response = requests.get(self._main_page + '/robots.txt')
        text = response.text

        self._has_robots = 200 == response.status_code  # Check robots.txt
        self._sitemap_in_robots = 'Sitemap' in text  # Detect sitemap in robots.txt
        del response

        if self._sitemap_in_robots:  # Path to  sitemap
            try:
                start = text.index('Sitemap')
                self._path_to_sitemap = text[text.index(self._tld, start) + len(self._tld): text.index('\n', start)]
                if self._path_to_sitemap.endswith('\r'):
                    self._path_to_sitemap = self._path_to_sitemap[:-2]
            except ValueError:
                self.path_to_sitemap = ''
        else:
            self._path_to_sitemap = ''

        if self._sitemap_in_robots:
            if '.gz' in self._path_to_sitemap:
                self._has_sitemap = True  # Detect sitemap.xml
                self._number_of_pages = 100  # Warning
            else:
                response = requests.get(self._main_page + self._path_to_sitemap)
                if response.status_code < 300:
                    self._has_sitemap = True  # Detect sitemap.xml
                    self._number_of_pages = response.text.count('http')  # Count pages in sitemap
                else:  # No sitemap
                    self._has_sitemap = False
                    self._number_of_pages = 0

        else:
            response = requests.get(self._main_page + '/sitemap.xml')
            if response.status_code == 200:
                self._has_sitemap = True  # Detect sitemap.xml
                self._number_of_pages = response.text.count('http')  # Count pages in sitemap
            else:  # No sitemap
                self._has_sitemap = False
                self._number_of_pages = 0

    def _check_security(self):
        """ Check main security params

        """
        self._is_personal_owner = self.url_data.name is not None  # Detect personal owner
        self._indexed_pages = 0 # Need to check number of pages for "google site:<sitename>"

        try:
            self._ssl_info = get_certificate(self._hostname, 443)
            self._subject = get_common_name(self._ssl_info)
            self._issuer = get_issuer(self._ssl_info)
            self._self_signed_ssl = False
            self._no_ssl = False
        except Exception as e:
            print(e)
            self._subject = self._issuer = None
            self._self_signed_ssl = True
            self._no_ssl = True

        if self.tld_data.subdomain == '' or self.tld_data.subdomain == 'www':
            self._valid_domain = True  # Second level domain
        elif self.tld_data.subdomain.count('.') == 0:
            self._valid_domain = self._domain in ['ru', 'en', 'www', 'api', 'mail', 'maps', 'images', 'music'] # Third level domain. Check domain's world // Can be improved
        else:
            self._valid_domain = False  # Fourth level domain

        if self._ns_servers is None:
            self._own_ns_servers = False
            self._free_host = True  # To make it dangerous
        else:
            for i in self._ns_servers:
                if self._domain in i:
                    self._own_ns_servers = True  # Default False
            for i in self._ns_servers:
                for server in []: # Can be improved
                    if i.lower() in server:
                        self._free_host = True  # Default False
                        break

        self._free_tld = self._tld in ['tk', 'ml', 'ga', 'cf', 'gq'] # Can be improved
        self._legal_tld = self._tld in ['ru', 'com', 'org', 'biz', 'info', 'name', 'pro', 'com.ru'] # Can be improved

    def _get_html(self):
        threads = []  # Multiple try to get html code
        response = None

        for i in range(2):
            _t = ThreadWithReturn(target=requests.get, args=(self._main_page))
            _t.daemon = True
            _t.start()
            threads.append(_t)

        for thread in threads:
            result = thread.join()
            if result and result.status_code < 300:
                response = result
                break
            else:
                print(f"Invalid response from {self._main_page}: {result}")

        if not response:
            print(f"Invalid response from {self._main_page}: {response}")
            self._html = "Can't get html"
            return

        self._has_genetator = '<meta name="generator"' in response.text  # Detect generator
        self._is_accessible = response.status_code == 200

        self._html = response.text
        self._html_len = len(response.text)  # Count length of HTML code of main page
        self._text = html2text(response.text)  # Extract text from HTML code
        self._text_len = len(html2text(response.text))  # Count length of text in HTML
        self._text_to_html_ratio = float(self._text_len / self._html_len)  # Count ratio of text and HTML code

        self._use_stats = False
        for i in ['analytics.js', 'watch.js', 'metrica.js']: # Can be improved
            if i in response.text:
                self._use_stats = True  # Detect using statistics
                break

    def get_dict(self) -> dict:
        """ Return json with all information about domain
        """
        result = {
            "domain": self._domain,
            "asn": self._asn,
            "tld": self._tld,
            "main_page": self._main_page,
            "html": self._html,
            "html_len": self._html_len,
            "text": self._text,
            "text_len": self._text_len,
            "text_ratio": self._text_to_html_ratio,
            "is_accessible": self._is_accessible,
            "use_generator": self._has_genetator,
            "use_stats": self._use_stats,
            "domain_age": self._domain_age,
            "legal_tld": self._legal_tld,
            "free_tld": self._free_tld,
            "has_robots": self._has_robots,
            "sitemap_in_robots": self._sitemap_in_robots,
            "path_to_sitemap": self._path_to_sitemap,
            "has_sitemap": self._has_sitemap,
            "number_of_pages": self._number_of_pages,
            "personal_owner": self._is_personal_owner,
            "has_cloudflare": self._has_cloudflare,
            "indexed_pages": self._indexed_pages,
            "ssl_gived_to": self._subject,
            "ssl_gived_by": self._issuer,
            "ip_addr": self._ip_addr,
            "ip_info": self._ip_info,
            "valid_domain": self._valid_domain,
            "free_ssl": self._free_ssl,
            "self_signed_ssl": self._self_signed_ssl,
            "no_ssl": self._no_ssl,
            "free_host": self._free_host,
            "ns_servers": self._ns_servers,
            "own_ns_servers": self._own_ns_servers,
            "ssl_info": self._ssl_info,
            "date": datetime.datetime.now().strftime("%d.%m.%Y")
        }

        return result

    def get_ml_dict(self) -> dict:
        """ Return json with all information about domain
        """
        result = {
            "domain": self._domain,
            "tld": self._tld,
            "html_len": self._html_len,
            "text_len": self._text_len,
            "text_ratio": self._text_to_html_ratio,
            "is_accessible": self._is_accessible,
            "use_generator": self._has_genetator,
            "use_stats": self._use_stats,
            "domain_age": self._domain_age,
            "legal_tld": self._legal_tld,
            "free_tld": self._free_tld,
            "has_robots": self._has_robots,
            "sitemap_in_robots": self._sitemap_in_robots,
            "has_sitemap": self._has_sitemap,
            "number_of_pages": self._number_of_pages,
            "personal_owner": self._is_personal_owner,
            "ssl_gived_by": self._issuer,
            "country": self._ip_info.get("asn_country_code"),
            "asn_date": self._ip_info.get("asn_date"),
            "valid_domain": self._valid_domain,
            "free_ssl": self._free_ssl,
            "self_signed_ssl": self._self_signed_ssl,
            "no_ssl": self._no_ssl,
            "free_host": self._free_host,
            "own_ns_servers": self._own_ns_servers,
            "san": len(get_alt_names(self._ssl_info)),
            
        }
        if self._ssl_info is not None:
            result["notbefore"] = f'{self._ssl_info.not_valid_before}'
            result["notafter"] = f'{self._ssl_info.not_valid_after}'
        else:
            result["notbefore"] = None
            result["notafter"] = None

        return result

    def get_json(self) -> str:
        return json.dumps(self.get_dict(), ensure_ascii=False, default=json_util.default)