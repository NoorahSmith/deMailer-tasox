import ipaddress
import socket
import logging
import validators
import whois
import colors

class deMailerValidator:

    def __init__(self,asset: str):
        
        """
        Validates a string to determine if it's IP or Domain
        """
        self.asset = asset

    
    def isPrivate(self) ->str:
        """
        Checking if the IP address belong to a private block

        Parameters
        ----------
        asset: str
            Takes a Domain or an IP address

        Return
        ------
        Boolean
            Returns 'True' if the IP is private and 'False' if not.
        """
        isPrivate = "-"
        try:
            isPrivate = ipaddress.ip_address(self.asset).is_private
            
        except Exception as e:
            logging.info(f"[-] Function isPrivate error during validation :: {e}")
        return isPrivate
        
    
    def geoIPValidation(self):
        
        """
        Validates an IP address and retrieves the domain name if exists (Reverse DNS lookup).
        It also checks if the provided IP is private or not.

        Parameters
        ----------
        Value: str
            IP Address

        Return
        ------
        IP Address: str
        Domain: str

        """
        
        # Initialize variables
        ip = None
        domain = None

        if validators.ipv4(self.asset) or validators.ipv6(self.asset):
            try:
                ip_address = ipaddress.ip_address(self.asset).exploded
                isPrivate = ipaddress.ip_address(ip_address).is_private
                # Filtering IP addresses
                if isPrivate == False:
                    ip = ip_address
                    # Retrieve Domain name
                    domain = socket.gethostbyaddr(ip_address)
            except Exception as e:
                logging.info(f"[-] Funtion geoIPValidation Error: {self.asset}<->{e}")

        return ip,domain
    
    def dnsLookUpValidation(self):

        """
        - It performs a IP validation with 'validators' 3rd party library.     
        - It's filtering the private IP
        - It performs Domain validation with 'validators' 3rd party library.

        Parameters
        ----------
        Domain or IP: str
            Get as input an IP address or a Domain Name

        Return
        ------
        Domain or IP: str
            Returns an IP address or a Domain Name

        """
        
        # Initialize variables
        domain_or_ip = None

        if validators.ipv4(self.asset) or validators.ipv6(self.asset):
            try:
                ip_address = ipaddress.ip_address(self.asset).exploded
                isPrivate = deMailerValidator(ip_address).isPrivate()
                # Filtering IP addresses
                if isPrivate == False:
                    domain_or_ip = ip_address
            except Exception as e:
                logging.info(f"[-] Function dnsLookUpValidation Error: {self.asset}<->{e}")

        elif validators.domain(self.asset):
            try:
                domain_or_ip = self.asset
            except Exception as e:
                logging.info(f"[-] DNS LookUp Error: {self.asset}<->{e}")
        
        return domain_or_ip
    
    def whoIsValidation(self):

        """
        - It performs a IP validation with 'validators' 3rd party library.     
        - It's filtering the private IP
        - It performs WhoIs LookUPs.

        Parameters
        ----------
        Doens't get any parameters

        Return
        ------
        Domain or IP: str
            Returns an IP address or a Domain Name
        WhoIs Info: dict
            Return Information for a given WhoIs request (IP or Domain).

        """
        
        # Initialize variables
        domain_or_ip = None
        whois_info = None

        if validators.ipv4(self.asset) or validators.ipv6(self.asset):
            try:
                ip_address = ipaddress.ip_address(self.asset).exploded
                isPrivate = deMailerValidator(ip_address).isPrivate()
                # Filtering IP addresses
                if isPrivate == False:
                    domain_or_ip = ip_address
                    whois_info = whois.whois(domain_or_ip)
            except Exception as e:
                logging.info(f"[-] Function whoIsValidation Error: {self.asset}<->{e}")

        elif validators.domain(self.asset):
            try:
                domain_or_ip = self.asset
                whois_info = whois.whois(domain_or_ip)
            except Exception as e:
                logging.info(f"[-] Function whoIsVaalidation Error: {self.asset}<->{e}")
        
        return domain_or_ip,whois_info