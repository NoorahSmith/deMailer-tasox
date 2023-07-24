from geolite2 import geolite2
import ipaddress
import logging
import dns.resolver
import socket
import validator
import validators
import deviator

class deMailerGeoIP:

    def __init__(self,enabled: bool =True):
        
        """
        Initiates a GeoIP look up

        Parameters
        ----------
        Enabled: True (by default)
        
        """
        self.enabled = enabled
        self.validator = validator
        self.deviator = deviator.deMailerDeviator()
        self.NaN = "-"
    
    def GeoIpLookUp(self,assets:list) ->dict:

        """
        It takes a list as input
        Performs a GeoIP lookup for a given IP or IPs.

        Parameters
        ----------
        asset: str
            Takes a Domain or an IP address

        Return
        ------
        Results: dict
            IP address: str
                The IP address that do a lookup
            Country Code: str
                The Country Code
            Country Name: str
                The Country Name
            Location: str
                The location 
            PrivateIP: str
                If it is private or not
        """

        reader = geolite2.reader()
        _geoIP = {}

        if len(assets) > 0:
            for asset in assets:
                
                privateIP = self.validator.deMailerValidator(asset).isPrivate()
                if asset in self.deviator._deMailerDeviator["ipAddressWhitelisting"]:
                    isWhitelisted = True
                else:
                    isWhitelisted = False

                if asset != None and privateIP == False and isWhitelisted == False:
                    match = None
                    try:
                        match = reader.get(asset)       
                    except Exception as e:
                        logging.error(e)

                    if match != None:
                        if "country" in match:
                            country_code = match["country"]["iso_code"]
                            country_name = match["country"]["names"]["en"]
                        else:
                            country_code = match["registered_country"]["iso_code"]
                            country_name = match["registered_country"]["names"]["en"]
                        
                        location_longitude = str(match["location"]["longitude"])
                        location_latitude = str(match["location"]["latitude"])
                        location = location_longitude + "," + location_latitude
                        # 'gethostbyaddr' returns a tuple. Domain seats on '0' index.
                        if asset not in _geoIP.keys():
                            dnsRecord = self.geoIP([asset])
                            dnsRecordList = dnsRecord.values()
                            dnsRecords = [record[0] for record in dnsRecordList]
                            _geoIP[asset] = {"DnsRecord":dnsRecords,"Ccode":country_code,"Country":country_name,"Location":location,"IsPrivate":privateIP,"IsWhitelisted":isWhitelisted}
                        else:
                            dnsRecord = self.geoIP([asset])
                            dnsRecordList = dnsRecord.values()
                            dnsRecords = [record[0] for record in dnsRecordList]
                            _geoIP[asset].update({"DnsRecord":dnsRecords,"Ccode":country_code,"Country":country_name,"Location":location,"IsPrivate":privateIP,"IsWhitelisted":isWhitelisted})

                    else:
                        dnsRecords = self.NaN
                        country_code = self.NaN
                        country_name = self.NaN
                        location_longitude = self.NaN
                        location_latitude = self.NaN
                        location = location_longitude + "," + location_latitude
                        _geoIP.update({asset:{"DnsRecord":dnsRecords,"Ccode":country_code,"Country":country_name,"Location":location,"IsPrivate":privateIP,"IsWhitelisted":isWhitelisted}})

                
                # will fall here, if the IP is private. No need to perform 'Whois' queries. 
                else:
                    dnsRecords = self.NaN
                    country_code = self.NaN
                    country_name = self.NaN
                    location_longitude = self.NaN
                    location_latitude = self.NaN
                    location = location_longitude + "," + location_latitude
                    _geoIP.update({asset:{"DnsRecord":dnsRecords,"Ccode":country_code,"Country":country_name,"Location":location,"IsPrivate":privateIP,"IsWhitelisted":isWhitelisted}})

            
        
                
        return _geoIP

    # 'assets' can be any ip or domain
    def geoIP(self,assets:list) ->dict():

        """
        It takes a list as input.
        Executes the 'geoIPValidation' from validator.py and saves the results into a dictionary.

        Parameters
        ----------
        Doesn't take any parameters

        Return
        ------
        results: dictionary
        """

        _nslookup = {}

        if len(assets) > 0:
            for asset in assets:
                
                # Check if the domain name is valid. Sometimes names with dots have similar pattern with domain names.
                validatedIp,resolvedDomain = self.validator.deMailerValidator(asset).geoIPValidation()

                if validatedIp != None and resolvedDomain != None:
                    # 'gethostbyaddr' returns a tuple. Domain seats on '0' index.
                    if validatedIp not in _nslookup.keys():
                        #nslookup_results_dict[asset] = [domain[0]]
                        _nslookup[asset] = [resolvedDomain[0]]
                    else:
                        #nslookup_results_dict[asset].append(domain[0])
                        _nslookup[asset].append(resolvedDomain[0])     
                else:
                    _nslookup[asset] = self.NaN                   
        
        return _nslookup