import re
import requests
import time


class Email(str):
    """ Email class for finding emails in text """
    email_pat = re.compile('[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-]+')
    email_tlds = set(['bank', 'com', 'org', 'net', 'int', 'edu', 'gov', 'mil'])
    
    @staticmethod
    def findall(text):
        """ find all emails in text, return as non-repetitive list of Email objects """
        found = set(re.findall(Email.email_pat, text))
        results = []
        for item in found:
            try:
                results.append(Email(item))
            except:
                pass
        return results

    @staticmethod
    def startswith_tld(test_str):
        """ does test_str start with one of the email_tlds? if so, return tld """
        for tld in Email.email_tlds:
            if test_str.lower().startswith(tld):
                return tld
        return False
    
    def __init__(self, email_addr: str):
        """ initialize email: input is email address in form of a string """
        self.email_addr = email_addr
        
        self.name, self.domain = re.split('@', email_addr)
        self.tld, self.country = None, None
        
        domain_list = re.split('\.', self.domain)

        # javascript has @md.x endings
        if domain_list[-1] == 'x' or domain_list[-1] in Domain.skip_types:
            raise TypeError(f"Invalid domain '{self.domain}'")

        if not all([x.isnumeric() for x in domain_list]):
    
            # if country attached, will be last 2 characters
            if len(domain_list) > 1 and len(domain_list[-1]) == 2:
                self.country = domain_list.pop().lower()

            # tld is 3 or 4 characters, may have garbage runon afterwards
            if len(domain_list) > 1:
                check_tld = Email.startswith_tld(domain_list[-1])
                if check_tld:
                    self.tld = check_tld
                    domain_list.pop()
                
        self.domain = '.'.join(domain_list)
        self.pwned_sleep = 1.7          # haveibeenpwned sleep time

    def __repr__(self):
        return f"Email('{self.email_addr}')"

    def __str__(self):
        domain_list = [self.domain]
        if self.tld:
            domain_list.append(self.tld)
        if self.country:
            domain_list.append(self.country)
        return self.name + '@' + '.'.join(domain_list)

    @property
    def tld(self):
        return self._tld
    
    @tld.setter
    def tld(self, value):
        if value and value.lower() not in Email.email_tlds:
                raise TypeError(f"Invalid top level domain '{value.lower()}'")
        self._tld = value
        
    def as_dict(self):
        """ return all vars for this object, strip off single underscores """
        return {re.sub('^_', '',x,count=1): y for x,y in self.__dict__.items()}

        
    @property
    def pwned(self):
        """ check email status on haveibeenpwned """

        # set up retry count
        max_attempts = 2

        # retry max number of times
        while (max_attempts > 0):

            max_attempts -= 1

            try:
                check = requests.get(
                        f'https://haveibeenpwned.com/api/v2/breachedaccount/{str(self)}',
                        headers = {'User-Agent': 'pwn_check'},
                        timeout = 2.0)
                self.last_error = None
            except Exception as e:
                self.last_error = e
                continue

            # translate http returns to status (text) and return value
            pwned_status_codes = {
                    200: ('address breached', True),
                    404: ('address not breached', False),
                    429: ('rate limit', None),
                    503: ('rate limit', None)
                    }
            self.pwned_status, return_value = pwned_status_codes.get(
                                check.status_code,
                                (f'unknown status code {check.status_code}', None))

            # if we have a return value, sleep first, then return it
            if return_value is not None:
                time.sleep(self.pwned_sleep)
                return return_value

            # should be a rate limit if we get here, if so, get sleep time
            if self.pwned_status == 'rate limit':
                headers = {x.lower(): y for x,y in check.headers.items()}
                self.pwned_sleep = float(headers.get('retry-after', self.pwned_sleep))

                if self.pwned_sleep > 80000:    # if full day pause, raise
                    raise TimeoutException

            # sleep before cycle
            time.sleep(self.pwned_sleep)

        # tried max_attempts, failed
        raise Exception(f'pwned {str(self)}: failed max retry, last error {self.last_error}')



from urllib.parse import urljoin
from urllib.parse import urlparse
import requests
import socket
import netaddr as na
from utils import ASNRoutingInfo
from bs4 import BeautifulSoup


class Domain():
    
    skip_types = set(['doc', 'docx', 'xls', 'xlsx', 'pdf', 'png', 'jpg', 'jpeg', 'zip', 'mp3', 'mp4', 'exe'])
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:12.0) Gecko/20100101 Firefox/12.0'}
    calendar_pat = re.compile('(calendar|events).*(/[0-9]{4}(/|-)[W]?[0-9]{1,2}|[0-9]{1,2}(/|-)[0-9]{1,2}(/|-)[0-9]{4}/|(exact_date|time_limit)~[0-9]{8,12})', re.I)
    calendar_action_pat = re.compile('(calendar|events).*(/action~|month/[0-9]{6})', re.I)

    def __init__(self, link, routing, verbose=False):
        if not link or len(link) < 1:
            raise TypeError('No link provided')
        self.link = link.split('//')[-1]
        self.parsed_url = urlparse(self.link)
        self.routing = routing
        self.error_count = 0
        
        self.cleanaddress = f'http://{self.parsed_url.path}'
        
        failed = False
        response = None
        try:
            if verbose: print(f'processing url {self.cleanaddress}')
            response = requests.get(self.cleanaddress, headers=Domain.headers, timeout=5.0)
            if response.status_code == 200:
                if 'FailureMode' in response.text:
                    failed = True
                    response = None
            else:
                failed = True
                    
        except Exception as e:
            failed = True
            
            
        if failed:
            try:
                self.cleanaddress = 'https://' + re.split('//', self.cleanaddress)[-1]
                if verbose: print(f'attempting secure url {self.cleanaddress}')
                response = requests.get(self.cleanaddress, headers=Domain.headers, timeout=5.0)
            except Exception as e:
                self.error_count += 1
                print(f'Unable to process {self.link}')
                raise e
        
        self.url = response.url
        self.parsed_url = urlparse(self.url)
        self.ip = na.IPAddress(socket.gethostbyname(self.parsed_url.netloc))
        self.__dict__.update(self.routing.ip_to_asn_dict(self.ip.value))
        self.__dict__['asn_number'] = self.routing.ip_to_asn(self.ip.value)
        new_clean = f'{self.parsed_url.scheme}://{self.parsed_url.netloc}/'
        if verbose: print(f'clean address should be {new_clean}')
        self.cleanaddress = new_clean
             
        self.host = self.cleanaddress.split('//')[-1]
        self.host = self.host.split('/')[0].lower()
        if verbose: print(f'host {self.host}')
        
        to_do_list = set([self.cleanaddress])
        visited, self.emails = set(), set()
        while to_do_list:
            if verbose: print(f'Visited: {len(visited)} To Do: {len(to_do_list)} Errors: {self.error_count}')
                
            # pop a link out of to do list
            link_to_do = to_do_list.pop()
            
            # keep track of which we have visited
            visited.add(link_to_do)
            
            if self.error_count > 3:
                threshold = int( 0.9 * len(visited))
                if self.error_count > threshold:
                    if verbose: print(f'breaking on {self.error_count} errors, threshold {threshold}.')
                    break
            
            try:
                if verbose: print(f'processing link {link_to_do}')
                response = requests.get(link_to_do, timeout=5.0)
            except Exception as e:
                if verbose: print(f'exception {e} error count {self.error_count}')
                try:
                    link_to_do = 'https://' + re.split('//', link_to_do)[-1]
                    if verbose: print(f'exception processing link {link_to_do}')
                    response = requests.get(link_to_do, timeout=5.0)
                except Exception as e:
                    if verbose: print(f'exception processing {link_to_do} {e} {self.error_count}')
                    self.error_count += 1
                    continue
            # if we did not get a clean response, end
            if response.status_code != 200:
                if verbose: print(f'bad status code {response.status_code}')
                self.error_count += 1
                continue
                
            # if this is not an html page, end
            if 'text' not in response.headers.get('Content-Type', 'pdf'):
                continue
            
            try:
                content = response.content.decode()
                email_list = Email.findall(content)
            except:
                self.error_count += 1
                continue
            if verbose: print(f'Found {len(email_list)} emails, {len(self.emails)} thus far.')
            self.emails.update(email_list)
            
            soup = BeautifulSoup(content, 'lxml')
            found = soup.findAll('a')
            if verbose: print(f'found {len(found)} links')
            for item in found:
                link_ref = item.get('href')
                if not link_ref:
                    continue
                
                # external reference
                if '//' in link_ref:
                    after_scheme = link_ref.split('//')[-1]
                    check_host = after_scheme.split('/')[0]
                    if check_host.lower() != self.host:
                        if verbose: print(f'skip external reference {link_ref}')
                        continue

                # clean up the url string
                parsed_url_path = urlparse(link_ref).path
                parsed_url_path = re.split('#', parsed_url_path)[0]
                parsed_url_path = re.split('&', parsed_url_path)[0]
                parsed_url_path = re.split('@', parsed_url_path)[0]
                endswith = parsed_url_path.split('.')[-1].lower()
                if endswith in Domain.skip_types:
                    continue
                
                new_link = urljoin(self.cleanaddress, parsed_url_path)

                # domain may have a calendar producer (php) (e.g., www.citizensfirststatebank.com)
                if Domain.calendar_pat.search(new_link) or Domain.calendar_action_pat.search(new_link):
                    if verbose: print(f'skip calendar reference {new_link}')
                    continue

                if new_link not in visited:
                    if verbose: print(f'adding new link {new_link}')
                    to_do_list.add(new_link)
                    
        self.links_visited = len(visited)