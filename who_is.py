import re
import logging
import validator
import deviator
import datetime

class deMailerWhoIs:

    def __init__(self,enabled: bool =True):

        """
        Performs a WhoIs requests either to IPs or Domains

        Parameters
        ----------
        Value: True (By default)
            Enabled
        """

        self.enabled = enabled
        self.validator = validator
        self.deviator = deviator.deMailerDeviator()
        self.NaN = "-"

    def convertToDateTime(self,dates:list):
        
        _datetimeList = []
        if dates and len(dates) >0:
            for date in dates:
                _datetimeList.append(str(date))
        
        return _datetimeList

    def domainWhois(self,domains: list) ->dict:

        """
        Performs a WhoIs request for the given domain

        Parameters
        ----------
        Value: str
            Domain Name

        Return
        ------
        WhoIs information: dict
        """

        _whoIs = {}

        if len(domains) > 0:
            for domain in domains:
                domain = re.search("([a-zA-Z0-9]\.|[a-zA-Z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,4}[A-Za-z]{2,9}",domain)
                
                if domain != None:
                    domain = domain.group()
                    if domain != "" and domain != None:
                        
                        # Domain validation
                        domainValidation,whois_info = self.validator.deMailerValidator(domain).whoIsValidation()

                        # check if the Domain is whitelisted -> it returns True or False
                        matched = self.deviator.matcher(self.deviator._deMailerDeviator["domainNameWhitelisting"],domain)

                        if domain in self.deviator._deMailerDeviator["domainNameWhitelisting"] or matched:
                            isWhitelisted = True
                        else:
                            isWhitelisted = False
                        
                        
                        #if whois_info != False and whois_info != None and whois_info:
                        try: 
                            if domainValidation != None and whois_info != None and isWhitelisted == False:
                                #if the domain exists
                                if whois_info.registrar and whois_info.registrar != None:
                                    registrar = whois_info.registrar
                                else:
                                    registrar = self.NaN
                                
                                if whois_info.registrant_org and whois_info.registrant_org != None:
                                    registrantOrg = whois_info.registrant_org
                                else:
                                    registrantOrg = self.NaN

                                if whois_info.whois_server and whois_info.whois_server != None:
                                    whois_server = whois_info.whois_server
                                else:
                                    whois_server = self.NaN
                                
                                if whois_info.creation_date and whois_info.creation_date != None:
                                    creation_date = whois_info.creation_date
                                    # The there are multiple dates in a list then convert them from this format: [datetime.datetime(2020, 11, 12, 12, 44, 29), ...] -> ['2020-11-12T12:44:29', ...] 
                                    if isinstance(creation_date,list):
                                        creation_date = self.convertToDateTime(creation_date)
                                else:
                                    creation_date = self.NaN
                                
                                if whois_info.updated_date and whois_info.updated_date != None:
                                    updated_date = whois_info.updated_date
                                    # The there are multiple dates in a list then convert them from this format: [datetime.datetime(2020, 11, 12, 12, 44, 29), ...] -> ['2020-11-12T12:44:29', ...] 
                                    if isinstance(updated_date,list):
                                        updated_date = self.convertToDateTime(updated_date)
                                else:
                                    updated_date = self.NaN 

                                if whois_info.name_servers and whois_info.name_servers != None:
                                    name_servers = whois_info.name_servers
                                else:
                                    name_servers = self.NaN
                                
                                # If all of them have no value then maybe are not domains.
                                _whoIs[domain] = {"registrant_org": registrantOrg,"domain_registrar":registrar,"whois_server":whois_server,"creation_date":creation_date,"updated_date":updated_date,"name_servers":name_servers,"IsWhitelisted":isWhitelisted}
                            else:
                                registrar = "No Results"
                                registrantOrg = "No Results"
                                whois_server = "No Resutls"
                                creation_date = "No Results"
                                updated_date = "No Results"
                                name_servers = "No Results"
                        except Exception as e:
                            logging.error(f'::Function Error->domainWhois ::{e}')

                        # If all of them have no value then maybe are not domains.
                        _whoIs[domain] = {"registrant_org": registrantOrg,"domain_registrar":registrar,"whois_server":whois_server,"creation_date":creation_date,"updated_date":updated_date,"name_servers":name_servers,"IsWhitelisted":isWhitelisted}
                        
        return _whoIs

    def ipWhois(self,ips: list) -> dict:

        """
        Performs a WhoIs request for the given IP

        Parameters
        ----------
        Value: str
            IP Address

        Return
        ------
        WhoIs information: dict
        """

        _ipwhois = {}

        if len(ips) > 0:
            for ip in ips:
                if ip !="" and ip != None:
                        
                    # Validates the IP and retieves the Domain Name
                    IpValidation,domain = self.validator.deMailerValidator(ip).geoIPValidation()
                    privateIP = self.validator.deMailerValidator(ip).isPrivate()
                    
                    if ip in self.deviator._deMailerDeviator["ipAddressWhitelisting"]:
                        isWhitelisted = True
                    else:
                        isWhitelisted = False
                    
                    try:
                        
                        if IpValidation !=None and domain[0] and privateIP == False and isWhitelisted == False:
                            
                            # Domain validation
                            domainValidation,whois_info = self.validator.deMailerValidator(domain[0]).whoIsValidation()
                            
                            #if the domain exists
                            if whois_info.registrar and whois_info.registrar != None:
                                registrar = whois_info.registrar
                            else:
                                registrar = self.NaN

                            if whois_info.registrant_org and whois_info.registrant_org != None:
                                registrantOrg = whois_info.registrant_org
                            else:
                                registrantOrg = self.NaN

                            if whois_info.whois_server and whois_info.whois_server != None:
                                whois_server = whois_info.whois_server
                            else:
                                whois_server = self.NaN

                            if whois_info.creation_date and whois_info.creation_date != None:
                                creation_date = whois_info.creation_date
                                # The there are multiple dates in a list then convert them from this format: [datetime.datetime(2020, 11, 12, 12, 44, 29), ...] -> ['2020-11-12T12:44:29', ...] 
                                if isinstance(creation_date,list):
                                    creation_date = self.convertToDateTime(creation_date)
                            else:
                                creation_date = self.NaN

                            if whois_info.updated_date and whois_info.updated_date != None:
                                updated_date = whois_info.updated_date
                                # The there are multiple dates in a list then convert them from this format: [datetime.datetime(2020, 11, 12, 12, 44, 29), ...] -> ['2020-11-12T12:44:29', ...] 
                                if isinstance(updated_date,list):
                                    updated_date = self.convertToDateTime(updated_date)
                            else:
                                updated_date = self.NaN 

                            if whois_info.name_servers and whois_info.name_servers != None:
                                name_servers = whois_info.name_servers
                            else:
                                name_servers = self.NaN

                            # If all of them have no value then maybe are not domains.
                            _ipwhois[ip] = {"registrant_org": registrantOrg,"domain_registrar":registrar,"whois_server":whois_server,"creation_date":creation_date,"updated_date":updated_date,"name_servers":name_servers,"IsPrivate":privateIP,"IsWhitelisted":isWhitelisted}

                        else:
                            registrar = "No Results"
                            registrantOrg = "No Results"
                            whois_server = "No Resutls"
                            creation_date = "No Results"
                            updated_date = "No Results"
                            name_servers = "No Results"

                            # If all of them have no value then maybe are not domains.
                            _ipwhois[ip] = {"registrant_org": registrantOrg,"domain_registrar":registrar,"whois_server":whois_server,"creation_date":creation_date,"updated_date":updated_date,"name_servers":name_servers,"IsPrivate":privateIP,"IsWhitelisted":isWhitelisted}

                    except Exception as e:
                        logging.error(f'::Function Error-> ipWhois::{e}')

        return _ipwhois