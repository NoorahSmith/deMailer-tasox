import ipaddress
import re
import logging
import colors

_deMailerDeviator = {
                                
                        "domainNameWhitelisting":['gmail.com'],
                        "emailWhitelisting":['','-',None,'tasos1@gmail.com'],
                        "ipAddressWhitelisting":["127.0.0.1","127.0.1.1","23.83.212.50"],
                        "UrlWhitelisting":[],
                    }

class deMailerDeviator:

    def __init__(self,**kwargs):
        """
        **kwargs -> whitelisted_ips=WHITELISTED_IPS,whitelisted_domains=WHITELISTED_DOMAINS,whitelisted_emails=WHITELISTED_EMAILS
        """
        
        
        for key, value in kwargs.items():
            if key == "whitelisted_ips":
                self.whitelisted_ips = value
                self.deviatorUpdater(whitelisted_ips=self.whitelisted_ips)
            if key == "whitelisted_domains":
                self.whitelisted_domains = value
                self.deviatorUpdater(whitelisted_domains=self.whitelisted_domains)
            if key == "whitelisted_emails":
                self.whitelisted_emails = value
                self.deviatorUpdater(whitelisted_emails=self.whitelisted_emails)

        
        self._deMailerDeviator = _deMailerDeviator
        
        """
        The _deMailerDeviator dictionary holds all the data you want to exclude. 

        _deMailerDeviator Keys
        ----------------------
        1.  domainNameWhitelisting
        2.  emailAddressWhitelisting
        3.  ipAddressWhitelisting
        4.  urlWhitelisting

        1. domainNameWhitelisting
        --------------
            List of all the Domains that you want to exclude.
        
        2. emailAddressWhitelisting
        ---------------
            List of all the Emails that you want to exclude.

        3.  ipAddressWhitelisting
        ---------------
            List of all the IP Addresses that you want to exclude.

        4. UrlWhitelisting
        ------
            List of all the Urls that you want to exclude.
        
        Example
        -------
        self._deMailerDeviator = { "domainNameWhitelisting":["test.com"], "emailWhitelisting":["admin@test.com"],"ipAddressWhitelisting":["127.0.0.1","127.0.1.1","23.83.212.50"],"UrlWhitelisting":["http://127.0.0.1"]}

        """
        

    def matcher(self,d,text) ->bool:
        """
        This function searches if any observable is whitelisted (excluded) by user.
        All the whitelisted (excluded) items are inside _deMailerDeviator dictionary.

        Arguments:
        ----------
        d: Items in _deMailerDeviator dictionary. Example: _deMailerDeviator["domainNameWhitelisting"]
        text: main string that we use to search inside. 
        """
        matched = False
        try:
            # d -> _deMailerDeviator is a list, for example: _deMailerDeviator["ipAddressWhitelisting"]->["127.0.0.1","127.0.1.1","23.83.212.50"]
            if isinstance(d,list):
                # Iterrate whitelisted items
                for whitelisted in d:
                    # Make sure the whitelist item is not empty, None or '-'
                    if whitelisted and whitelisted != None and whitelisted != "-":
                        # Look for * in the whitelisted item
                        match_asterisc = re.search(r'\*',whitelisted)
                        # if * exist in the whitelisted listed, for example: [".*google.com"]
                        if match_asterisc and match_asterisc !=None:
                            #print(pattern + '<>' + item)
                            # Then search for whitelisted pattern in the text
                            match = re.search(whitelisted,text)
                            # If you get results
                            if match and match != None:
                                # It means our string found in exclusion list.
                                matched = True
                        # If * is not found in whitelisted list
                        elif not match_asterisc:
                            # Search if whitelisted item matches with the provided text (Can be domain, email)
                            match = re.search(whitelisted,text)
                            # If you get results
                            if match and match !=None:
                                # It means our string found in exclusion list.
                                matched = True
        except Exception as e:
            logging.error(f"{colors.style.RED}[-] Error on matcher() :: {e}{colors.style.RESET}")
        
        return matched

    def deviatorUpdater(self,**kwargs):
        """
        Updates the _deMailerDeviator with exclusions that belongs to: emails, domains, ips and urls
        Those exlusions provided by user with flags: --exclude_ips, --exclude_domains, --exclude_emails
        """
        for key, value in kwargs.items():
            #print("%s == %s" % (key, value))
            if value and value !=None and len(value)>0:
                if key == "whitelisted_ips":
                    for ips in value:
                        _ips = [str(ip) for ip in ipaddress.IPv4Network(ips)]
                        self.updateIPDeviator(_ips)

                if key == "whitelisted_domains":
                    domains = value
                    self.updateDomainDeviator(domains)
                
                if key == "whitelisted_emails":
                    emails = value
                    self.updateEmailDeviator(emails)

    def deMailerZeusKeySearcher(self,element:dict, *keys):
        """
        Check if *keys (nested) exists in `element` (dict).

        Reference
        ---------
        https://stackoverflow.com/questions/43491287/elegant-way-to-check-if-a-nested-key-exists-in-a-dict 
        """
        if not isinstance(element, dict):
            raise AttributeError('deMailerZeusKeySearcher() expects dict as first argument.')
        if len(keys) == 0:
            raise AttributeError('deMailerZeusKeySearcher() expects at least two arguments, one given.')

        _element = element
        for key in keys:
            try:
                _element = _element[key]
            except KeyError:
                return False
        return True

    def updateDomainDeviator(self,domains:list):

        if not isinstance(domains, list):
            raise AttributeError('updateDomainDeviator() expects list as first argument.')
        
        if len(domains) == 0:
            raise AttributeError('updateDomainDeviator() expects a list with length >0 as first argument.')

        # Check if 'domainNameWhitelisting' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(_deMailerDeviator,"domainNameWhitelisting")

        if not keyExists:
            _deMailerDeviator["domainNameWhitelisting"] = []

        if len(domains) > 0:
            for domain in domains:
                _deMailerDeviator["domainNameWhitelisting"].append(domain)
    
    def updateEmailDeviator(self,emails:list):

        if not isinstance(emails, list):
            raise AttributeError('updateEmailDeviator() expects list as first argument.')
        
        if len(emails) == 0:
            raise AttributeError('updateEmailDeviator() expects a list with length >0 as first argument.')

        # Check if 'emailWhitelisting' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(_deMailerDeviator,"emailWhitelisting")

        if not keyExists:
            _deMailerDeviator["emailWhitelisting"] = []

        if len(emails) > 0:
            for email in emails:
                _deMailerDeviator["emailWhitelisting"].append(email)

    def updateIPDeviator(self,ips:list):

        if not isinstance(ips, list):
            raise AttributeError('updateIPDeviator() expects list as first argument.')
        
        if len(ips) == 0:
            raise AttributeError('updateIPDeviator() expects a list with length >0 as first argument.')

        # Check if 'ipAddressWhitelisting' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(_deMailerDeviator,"ipAddressWhitelisting")

        if not keyExists:
            _deMailerDeviator["ipAddressWhitelisting"] = []

        if len(ips) > 0:
            for ip in ips:
                _deMailerDeviator["ipAddressWhitelisting"].append(ip)
    
    def updateUrlDeviator(self,urls:list):

        if not isinstance(urls, list):
            raise AttributeError('updateUrlDeviator() expects list as first argument.')
        
        if len(urls) == 0:
            raise AttributeError('updateUrlDeviator() expects a list with length >0 as first argument.')

        # Check if 'UrlWhitelisting' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(_deMailerDeviator,"UrlWhitelisting")

        if not keyExists:
            _deMailerDeviator["UrlWhitelisting"] = []

        if len(urls) > 0:
            for url in urls:
                _deMailerDeviator["UrlWhitelisting"].append(url)    