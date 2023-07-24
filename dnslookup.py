import ipaddress
import socket
import dns.resolver
import logging
import validators
import validator
import deviator

class deMailerDNS():

    def __init__(self,enabled: bool =True):
        
        """
        Initiates a DNS look up

        Parameters
        ----------
        Enabled: True (by default)
        """
        
        self.enabled = enabled
        self.validator = validator
        self.deviator = deviator.deMailerDeviator()
        self.NaN = "-"

    def lookupDNS(self,domains: list) ->dict:
        
        """
        Performs a DNS Lookup to retrieve the records of a Domain.

        Parameters
        ----------
        Value: str
            Domain Name
        
        Return
        ------
        domainLookUP: dict
            Returns the A,AAAA,CNAME, TXT, PTR, SOA, MX records of a domain
        """
        

        _domainLookUP = {}
        _final_domainLookUP = {}
        
        if len(domains) > 0:
            for domain in domains:    
                # Strip '\n' created by WrapText inside 'printWhois' function.
                domain = domain.strip()

                # Check if the domain name is valid. Sometimes names with dots have similar pattern with domain names.
                asset = self.validator.deMailerValidator(domain).dnsLookUpValidation()
                
                # check if the Domain is whitelisted -> it returns True or False
                matched = self.deviator.matcher(self.deviator._deMailerDeviator["domainNameWhitelisting"],asset)

                if asset in self.deviator._deMailerDeviator["domainNameWhitelisting"] or matched:
                    isWhitelisted = True
                else:
                    isWhitelisted = False

                cnames = self.NaN
                ass = self.NaN
                aaaas = self.NaN
                txts = self.NaN
                ptrs = self.NaN
                soas = self.NaN
                mxs = self.NaN
                # Check if domain resolves to any IP.
                if asset != None and asset and asset !="" and isWhitelisted == False:
                    #Initialize dict.
                    _domainLookUP.update({asset:{'A':[],'AAAA':[],'CNAME':[],'TXT':[],'PTR':[],'SOA':[],'MX':[],'IsWhitelisted':isWhitelisted}})
                    try:
                        cnames = dns.resolver.resolve(asset, 'CNAME')
                        if len(cnames) > 0 and isinstance(cnames, dns.resolver.Answer):
                            for cname in cnames:
                                if cname and cname != "":
                                    _domainLookUP[asset]["CNAME"].append(cname.to_text())                            
                    except Exception as e:
                        _domainLookUP[asset]["CNAME"].append(self.NaN)
                        logging.info(e)
                    
                    try:
                        ass = dns.resolver.resolve(asset, 'A')
                        if len(ass) > 0 and isinstance(ass, dns.resolver.Answer):
                            for a in ass:
                                if a and a!="":
                                    _domainLookUP[asset]["A"].append(a.to_text())                        
                    except Exception as e:
                        _domainLookUP[asset]["A"].append(self.NaN)
                        logging.info(e)
                    
                    try:    
                        aaaas = dns.resolver.resolve(asset, 'AAAA')
                        if len(aaaas) > 0 and isinstance(aaaas, dns.resolver.Answer):
                            for aaaa in aaaas:
                                _domainLookUP[asset]["AAAA"].append(aaaa.to_text())
                    except Exception as e:
                        _domainLookUP[asset]["AAAA"].append(self.NaN)
                        logging.info(e)
                    
                    try:
                        txts = dns.resolver.resolve(asset, 'TXT')
                        if len(txts) > 0 and isinstance(txts, dns.resolver.Answer):
                            for txt in txts:
                                if txt and txt !="":
                                    _domainLookUP[asset]["TXT"].append(txt.to_text())
                    except Exception as e:
                        _domainLookUP[asset]["TXT"].append(self.NaN)
                        logging.info(e)

                    try:    
                        ptrs = dns.resolver.resolve(asset, 'PTR')
                        if len(ptrs) > 0 and isinstance(ptrs, dns.resolver.Answer):
                            for ptr in ptrs:
                                if ptr and ptr != "":
                                    _domainLookUP[asset]["PTR"].append(ptr.to_text())
                    except Exception as e:
                        _domainLookUP[asset]["PTR"].append(self.NaN)
                        logging.info(e)

                    try:
                        soas = dns.resolver.resolve(asset, 'SOA')
                        if len(soas) > 0 and isinstance(soas, dns.resolver.Answer):
                            for soa in soas:
                                if soa and soa !="":
                                    _domainLookUP[asset]["SOA"].append(soa.to_text())
                    except Exception as e:
                        _domainLookUP[asset]["SOA"].append(self.NaN)
                        logging.info(e)

                    try:
                        mxs = dns.resolver.resolve(asset, 'MX')
                        if len(mxs) > 0 and isinstance(mxs, dns.resolver.Answer):
                            for mx in mxs:
                                if mx and mx !="":
                                    _domainLookUP[asset]["MX"].append(mx.to_text())
                    except Exception as e:
                        _domainLookUP[asset]["MX"].append(self.NaN)
                        logging.info(e)

                elif asset != None and asset and asset !="" and isWhitelisted == True:
                    #Initialize dict.
                    cnames = self.NaN
                    ass = self.NaN
                    aaaas = self.NaN
                    txts = self.NaN
                    ptrs = self.NaN
                    soas = self.NaN
                    mxs = self.NaN
                    _domainLookUP.update({asset:{'A':[ass],'AAAA':[aaaas],'CNAME':[cnames],'TXT':[txts],'PTR':[ptrs],'SOA':[soas],'MX':[mxs],'IsWhitelisted':isWhitelisted}})

                for k in list(_domainLookUP[asset].keys()):
                    # Exclude the key 'IsWhitelisted' becaue is bool and will fail on the following check.
                    if k != "IsWhitelisted":
                        # if the lenght of the list is equal 0, it means the list doesn't contain values and should be popped from the dictionary
                        if len(_domainLookUP[asset][k]) == 0:
                            _domainLookUP[asset].pop(k)                        
                
                # Remove from dictionary Keys and their values where ALL the values are "-"
                # No reason to print them to screen
                _final_domainLookUP = {k: v for k, v in _domainLookUP.items() if v}

                #print(final_domainlookup_results_dict)
        return _final_domainLookUP