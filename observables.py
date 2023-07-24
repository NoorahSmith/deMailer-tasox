import logging

class deMailerObservables:

    def __init__(self):

        # Instantiate parent properties/methods
        #super().__init__()

        self._deMailerObservables = {"observables":{}}
        """
        observables
        ------------
        Urls: dict
            url: dict
                "origin": str
                "vtURLscore": str,
                "ctiURLscore": str,
                "ctiURLtag": list
        
        Domains: dict
            domain: dict
                "origin": str,
                "vtURLscore": str,
                "ctiURLscore": str,
                "ctiURLtag": list
        
        Emails: dict
            email: dict
                "origin": str
                "vtURLscore": str,
                "ctiURLscore": str,
                "ctiURLtag": list
        
        IPs: dict
            ip: dict
                "origin": str,
                "vtURLscore": str,
                "ctiURLscore": str,
                "ctiURLtag": list

            Example
            -------
            self._deMailerObservables = {observables:{
                                            "urls":{"http://thisisnotmalicious.com":{"origin":"","vtURLscore":"10/50","ctiURLscore","50","ctiURLtag":["Emotet"]}},
                                            "ips":{"134.12.34.87":{"origin":"","vtURLscore":"10/50","ctiURLscore","50","ctiURLtag":["Emotet"]}},
                                            "domains":{"thisisnotmalicious.com":{"origin":"","vtURLscore":"10/50","ctiURLscore","50","ctiURLtag":["Emotet"]}},
                                            "emails":{"test@test.com":{"origin":"","vtURLscore":"10/50","ctiURLscore","50","ctiURLtag":["Emotet"]}}
                                        }}
        
        """
    
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

    def addUrlObservables(self,observables:list):
        
        """
        This function adds Urls that found inside the e-mail to '_deMailerObservables'
        
        Parameters
        ----------
        observables: list
        
        Returns
        -------
        _deMailerObservables: dict
            The dictionary with all its values
        """

        if not isinstance(observables, list):
            raise AttributeError('addUrlObservables() expects list as first argument.')
        
        if len(observables) == 0:
            raise AttributeError('addUrlObservables() expects a list with length >0 as first argument.')
        
        
        # Check if 'urls' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables")
    
        if keyExists:
            # Check if 'urls' key exists in the dictionary
            keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","urls")
            if not keyExists:
                self._deMailerObservables["observables"].update({"urls":{}})
            
        else:
            self._deMailerObservables["observables"] = {}
            self._deMailerObservables["observables"].update({"urls":{}})
        
        for observable in observables:
            observableExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","urls",observable)
            if not observableExists:
                self._deMailerObservables["observables"]["urls"].update({observable:{}})
        
        return self._deMailerObservables["observables"]["urls"]

    def addIPObservables(self,observables:list):
        """
        This function adds IPs that found inside the e-mail to '_deMailerObservables'
        
        Parameters
        ----------
        observables: list
        
        Returns
        -------
        _deMailerObservables: dict
            The dictionary with all its values
        """

        if not isinstance(observables, list):
            raise AttributeError('addUrlObservables() expects list as first argument.')
        
        if len(observables) == 0:
            raise AttributeError('addUrlObservables() expects a list with length >0 as first argument.')
        
        
        # Check if 'ips' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables")
    
        if keyExists:
            # Check if 'ips' key exists in the dictionary
            keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","ips")
            if not keyExists:
                self._deMailerObservables["observables"].update({"ips":{}})
            
        else:
            self._deMailerObservables["observables"] = {}
            self._deMailerObservables["observables"].update({"ips":{}})
        
        for observable in observables:
            observableExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","ips",observable)
            if not observableExists:
                self._deMailerObservables["observables"]["ips"].update({observable:{}})
        
        return self._deMailerObservables["observables"]["ips"]
    
    def addDomainObservables(self,observables:list):
        """
        This function adds Domains that found inside the e-mail to '_deMailerObservables'
        
        Parameters
        ----------
        observables: list
        
        Returns
        -------
        _deMailerObservables: dict
            The dictionary with all its values
        """

        if not isinstance(observables, list):
            raise AttributeError('addUrlObservables() expects list as first argument.')
        
        if len(observables) == 0:
            raise AttributeError('addUrlObservables() expects a list with length >0 as first argument.')
        
        
        # Check if 'domains' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables")
    
        if keyExists:
            # Check if 'domains' key exists in the dictionary
            keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","domains")
            if not keyExists:
                self._deMailerObservables["observables"].update({"domains":{}})
            
        else:
            self._deMailerObservables["observables"] = {}
            self._deMailerObservables["observables"].update({"domains":{}})
        
        for observable in observables:
            observableExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","domains",observable)
            if not observableExists:
                self._deMailerObservables["observables"]["domains"].update({observable:{}})
        
        return self._deMailerObservables["observables"]["domains"]

    def addEmailObservables(self,observables:list):
        """
        This function adds Emails that found inside the e-mail to '_deMailerObservables'
        
        Parameters
        ----------
        observables: list
        
        Returns
        -------
        _deMailerObservables: dict
            The dictionary with all its values
        """

        if not isinstance(observables, list):
            raise AttributeError('addUrlObservables() expects list as first argument.')
        
        if len(observables) == 0:
            raise AttributeError('addUrlObservables() expects a list with length >0 as first argument.')
        
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables")
    
        if keyExists:
            # Check if 'emails' key exists in the dictionary
            keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","emails")
            if not keyExists:
                self._deMailerObservables["observables"].update({"emails":{}})
            
        else:
            self._deMailerObservables["observables"] = {}
            self._deMailerObservables["observables"].update({"emails":{}})
        
        for observable in observables:
            observableExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","emails",observable)
            if not observableExists:
                self._deMailerObservables["observables"]["emails"].update({observable:{}})
        
        return self._deMailerObservables["observables"]["emails"]
    
    def updateUrlObservablesFromDeviator(self,urls:list,deMailerDeviator:dict,*keys):
        
        """
        This function updates the 'urls' key inside '_deMailerObservables'. 
        Whatever you add inside this dict then is going to be printed in the 'Observables' table.
        
        Parameters
        ----------
        urls: list
            Key to update in the dictionary
        deMailerDeviator: dict
        
        Returns
        -------
        Doesn't return a value
        """

        if len(urls) == 0:
            raise(f"updateUrlObservables() expect first argument not to be null")

        if not isinstance(deMailerDeviator, dict):
            raise AttributeError('updateUrlObservables() expects a dictionary as first argument.')
        
        if len(deMailerDeviator) == 0:
            raise AttributeError('updateUrlObservables() expects a dictionary with length >0 as first argument.')
        
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables")
    
        if keyExists:
            # Check if 'emails' key exists in the dictionary
            keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","urls")
            if not keyExists:
                logging.error("[-] Can't update a the key 'urls' because doesn't exists in the _deMailerObservables dict.")
        

        if len(deMailerDeviator) >0 and len(urls)>0:
            
            for url in self._deMailerObservables["observables"]["urls"].keys():
                for url2 in urls:
                    url = url.strip()
                    url2 = url2.strip()
                    if url2 == url and len(keys) > 0:
                        for key in keys:
                            try:
                                if url not in deMailerDeviator["UrlWhitelisting"]:
                                    self._deMailerObservables["observables"]["urls"][url].update({key:False})
                                else:
                                    self._deMailerObservables["observables"]["urls"][url].update({key:True})
                            except KeyError as e:
                                logging.error(f"[-] Function updateUrlObservables() error :: {e}")
    
    def updateIPObservablesFromZeus(self,ips:list,deMailerZeus:dict,*keys):
        
        """
        This function updates IPs that found inside the e-mail to '_deMailerObservables'
        
        Parameters
        ----------
        ips: str
            Key to update in the dictionary
        deMailerZeus: dict
        
        Returns
        -------
        _deMailerObservables: dict
            The dictionary with all its values
        """

        if len(ips) == 0:
            raise(f"updateIPObservables() expect first argument not to be null")

        if not isinstance(deMailerZeus, dict):
            raise AttributeError('updateIPObservables() expects a dictionary as first argument.')
        
        if len(deMailerZeus) == 0:
            raise AttributeError('updateIPObservables() expects a dictionary with length >0 as first argument.')
        
        
        # Check if 'ips' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables")
    
        if keyExists:
            # Check if 'ips' key exists in the dictionary
            keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","ips")
            if not keyExists:
                logging.error("[-] Can't update a the key 'ips' because doesn't exists in the _deMailerObservables dict.")
        

        if len(deMailerZeus) >0 and len(ips)>0:
            
            for ip in self._deMailerObservables["observables"]["ips"].keys():
                for ip2 in ips:
                    ip = ip.strip()
                    ip2 = ip2.strip()
                    if ip2 == ip and len(keys) == 0:
                        self._deMailerObservables["observables"]["ips"][ip].update(deMailerZeus[ip])
                    elif ip2 == ip and len(keys) > 0:
                        for key in keys:
                            try:
                                value = deMailerZeus[ip][key]
                                self._deMailerObservables["observables"]["ips"][ip].update({key:value})
                            except KeyError as e:
                                logging.error(f"[-] Function updateIPObservables() error. The {key} not exists in {deMailerZeus[ip]} :: {e}")

    def updateDomainObservablesFromZeus(self,domains:list,deMailerZeus:dict,*keys):
        
        """
        This function updates Domains that found inside the e-mail to '_deMailerObservables'
        
        Parameters
        ----------
        domains: list
            Domains to update in the dictionary
        deMailerZeus: dict
        
        Returns
        -------
        _deMailerObservables: dict
            The dictionary with all its values
        """

        if len(domains) == 0:
            raise(f"updateDomainObservables() expect first argument not to be null")

        if not isinstance(deMailerZeus, dict):
            raise AttributeError('updateDomainObservables() expects a dictionary as first argument.')
        
        if len(deMailerZeus) == 0:
            raise AttributeError('updateDomainObservables() expects a dictionary with length >0 as first argument.')
        
        
        # Check if 'domains' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables")
    
        if keyExists:
            # Check if 'domains' key exists in the dictionary
            keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","domains")
            if not keyExists:
                logging.error("[-] Can't update a the key 'domains' because doesn't exists in the _deMailerObservables dict.")
        

        if len(deMailerZeus) >0 and len(domains)>0:
            
            for domain in self._deMailerObservables["observables"]["domains"].keys():
                for domain2 in domains:
                    domain = domain.strip()
                    domain2 = domain2.strip()
                    if domain2 == domain and len(keys) == 0:
                        self._deMailerObservables["observables"]["domains"][domain].update(deMailerZeus[domain])
                    elif domain2 == domain and len(keys) > 0:
                        for key in keys:
                            try:
                                value = deMailerZeus[domain][key]
                                self._deMailerObservables["observables"]["domains"][domain].update({key:value})
                            except KeyError as e:
                                logging.error(f"[-] Function updateDomainObservables() error. The {key} not exists in {deMailerZeus[domain]} :: {e}")
    
    def updateEmailObservablesFromDeviator(self,emails:list,deMailerDeviator:dict,*keys):
        
        """
        This function updates the e-mail dict inside '_deMailerObservables'. 
        Whatever you add inside this dict then is going to be printed in the 'Observables' table.
        
        Parameters
        ----------
        emails: list
            Key to update in the dictionary
        deMailerDeviator: dict
        
        Returns
        -------
        _deMailerObservables: dict
            The dictionary with all its values
        """

        if len(emails) == 0:
            raise(f"updateEmailObservables() expect first argument not to be null")

        if not isinstance(deMailerDeviator, dict):
            raise AttributeError('updateEmailObservables() expects a dictionary as first argument.')
        
        if len(deMailerDeviator) == 0:
            raise AttributeError('updateEmailObservables() expects a dictionary with length >0 as first argument.')
        
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables")
    
        if keyExists:
            # Check if 'emails' key exists in the dictionary
            keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","emails")
            if not keyExists:
                logging.error("[-] Can't update a the key 'emails' because doesn't exists in the _deMailerObservables dict.")
        

        if len(deMailerDeviator) >0 and len(emails)>0:
            
            for email in self._deMailerObservables["observables"]["emails"].keys():
                for email2 in emails:
                    email = email.strip()
                    email2 = email2.strip()
                    if email2 == email and len(keys) > 0:
                        for key in keys:
                            try:
                                if email not in deMailerDeviator["emailWhitelisting"]:
                                    self._deMailerObservables["observables"]["emails"][email].update({key:False})
                                else:
                                    self._deMailerObservables["observables"]["emails"][email].update({key:True})
                            except KeyError as e:
                                logging.error(f"[-] Function updateEmailObservables() error :: {e}")

    def updateUrlObservables(self,urls:list,properties:dict,deMailerObservables:dict):
        """
        This function updates the 'urls' key inside '_deMailerObservables'. 
        Whatever you add inside this dict then is going to be printed in the 'Observables' table.
        
        Parameters
        ----------
        urls: list
            Key to update in the dictionary
        properties: dict
        
        Returns
        -------
        Doesn't return a value
        """

        if not isinstance(urls, list):
            raise AttributeError('updateUrlObservables() expects a list as first argument.')
        if not isinstance(properties, dict):
            raise AttributeError('updateUrlObservables() expects a dictionary as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('updateUrlObservables() expects a dictionary as third argument.')
        
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables")
    
        #if keyExists:
        #    # Check if 'emails' key exists in the dictionary
        #    keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","urls")
        #    if not keyExists:
        #        logging.error("[-] Can't update a the key 'urls' because doesn't exists in the _deMailerObservables dict.")
        
        if keyExists:
            # Check if 'urls' key exists in the dictionary
            keyTypeExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables","urls")
            if not keyTypeExists:
                deMailerObservables["observables"].update({"urls":{}})
            
        else:
            deMailerObservables["observables"] = {}
            deMailerObservables["observables"].update({"urls":{}})

        # Add Url to observables dict if not exists
        self.addUrlObservables(urls)

        if len(properties) >0 and len(urls) >0:
            
            for url in self._deMailerObservables["observables"]["urls"].keys():
                for url2 in urls:
                    url = url.strip()
                    url2 = url2.strip()

                    if url == url2 and url2 in deMailerObservables["observables"]["urls"].keys():
                        try:
                            deMailerObservables["observables"]["urls"][url].update(properties)
                        except KeyError as e:
                            logging.error(f"[-] Function updateUrlObservables() error :: {e}")

                    elif url == url2 and url2 not in deMailerObservables["observables"]["urls"].keys():
                        try:
                            deMailerObservables["observables"]["urls"].update({url:{properties}})
                        except KeyError as e:
                            logging.error(f"[-] Function updateUrlObservables() error :: {e}")
    
    def DEPRECATED_updateIPObservables(self,ips:list,properties:dict,deMailerObservables:dict,service):
        """
        This function updates the 'ips' key inside '_deMailerObservables'. 
        Whatever you add inside this dict then is going to be printed in the 'Observables' table.
        
        Parameters
        ----------
        ips: list
            Key to update in the dictionary
        properties: dict
        
        Returns
        -------
        Doesn't return a value
        """

        if not isinstance(ips, list):
            raise AttributeError('updateIPObservables() expects a list as first argument.')
        if not isinstance(properties, dict):
            raise AttributeError('updateIPObservables() expects a dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('updateIPObservables() expects a dict as third argument.')
        
        analysis_stats_key = None
        if service == "vt":
            analysis_stats_key = "vt_analysis_stats"
        elif service == "opencti":
            analysis_stats_key = "opencti_analysis_stats"
        else:
            service = None
        
        # Check if 'observables' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables")
        
        if keyExists:
            # Check if 'urls' key exists in the dictionary
            keyIPsExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables","ips")
            if not keyIPsExists:
                deMailerObservables["observables"].update({"ips":{}})
            
        else:
            deMailerObservables["observables"] = {}
            deMailerObservables["observables"].update({"ips":{}})
                
        # Add IP to observables dict if not exists
        self.addIPObservables(ips)

        keyStatsKeyExists = None

        if len(properties) >0 and len(ips) >0:
            for ip in deMailerObservables["observables"]["ips"].keys():
                for ip2 in ips:
                    ip = ip.strip()
                    ip2 = ip2.strip()

                    if ip == ip2 and ip2 in deMailerObservables["observables"]["ips"].keys():
                        try:
                            if analysis_stats_key != None:
                                keyStatsKeyExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables","ips",ip2,analysis_stats_key)
                            
                                if keyStatsKeyExists == True:
                                    deMailerObservables["observables"]["ips"][ip2][analysis_stats_key].update(properties)
                                elif keyStatsKeyExists == False:
                                    deMailerObservables["observables"]["ips"][ip2][analysis_stats_key]=properties
                            
                            elif analysis_stats_key ==None:
                                deMailerObservables["observables"]["ips"][ip2].update(properties)

                        except KeyError as e:
                            logging.error(f"[-] Function updateIPObservables() error :: {e}")

                    elif ip == ip2 and ip2 not in deMailerObservables["observables"]["ips"].keys():
                        try:
                            deMailerObservables["observables"]["ips"][ip2] = {}
                            if analysis_stats_key != None:
                                keyStatsKeyExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables","ips",ip2,analysis_stats_key)
                            
                                if keyStatsKeyExists ==True:    
                                    deMailerObservables["observables"]["ips"][ip2][analysis_stats_key].update(properties)

                                if keyStatsKeyExists ==False:    
                                    deMailerObservables["observables"]["ips"][ip2].update({analysis_stats_key:properties})
                                
                            elif keyStatsKeyExists ==None:
                                deMailerObservables["observables"]["ips"][ip2].update(properties)
                        except KeyError as e:
                            logging.error(f"[-] Function updateIPObservables() error :: {e}")

    def updateIPObservables(self,ips:list,deMailerZeus:dict,deMailerObservables:dict,service):
        """
        This function updates the 'ips' key inside '_deMailerObservables'. 
        Whatever you add inside this dict then is going to be printed in the 'Observables' table.
        
        Parameters
        ----------
        ips: list
            Key to update in the dictionary
        deMailerZeus: dict
        
        Returns
        -------
        Doesn't return a value
        """

        if not isinstance(ips, list):
            raise AttributeError('updateIPObservables() expects a list as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('updateIPObservables() expects a dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('updateIPObservables() expects a dict as third argument.')
        
        analysis_stats_key = None
        if service == "vt":
            analysis_stats_key = "last_analysis_stats"
        elif service == "opencti":
            analysis_stats_key = "opencti_analysis_stats"
        else:
            service = None
        
        # Check if 'observables' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables")
        
        if keyExists:
            # Check if 'ips' key exists in the dictionary
            keyIPsExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables","ips")
            if not keyIPsExists:
                deMailerObservables["observables"].update({"ips":{}})
            
        else:
            deMailerObservables["observables"] = {}
            deMailerObservables["observables"].update({"ips":{}})


        # Retrieve a list of 'VirusTotalScans'
        keyExists = self.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans")
        ipScanningKeyList = None
        ipScanningResults = None
        if keyExists:
            firstLevelKeys = list(deMailerZeus["VirusTotalScans"])
            if len(firstLevelKeys) >0:
                # Returns 'ip_scanning' key in list format -> ['ip_scanning']
                ipScanningKeyList = [x for x in firstLevelKeys if x == "ip_scanning"]
                if len(ipScanningKeyList) >0:
                    # Convert to string
                    ipScanningKeyStr = ipScanningKeyList[0]
                    # Retrieve 'VirusTotalScans' results for IP scanning 
                    # {"VirusTotalScans": {"ip_scanning": { ...} }
                    ipScanningResults = deMailerZeus["VirusTotalScans"][ipScanningKeyStr]

        # Add IP to observables dict if not exists
        self.addIPObservables(ips)

        keyStatsKeyExists = None

        if len(deMailerZeus) >0 and len(ips) >0 and ipScanningKeyList != None:
            for ip in deMailerObservables["observables"]["ips"].keys():
                for ip2 in ips:
                    ip = ip.strip()
                    ip2 = ip2.strip()

                    if ip == ip2 and ip2 in deMailerObservables["observables"]["ips"].keys() and ip in list(ipScanningResults):
                        # Retrieve the 'last_analysis_stats' from deMailerZeus after normalization
                        vtIPScanLastAnalysisStats = ipScanningResults[ip]["last_analysis_stats"]
                        try:
                            if analysis_stats_key != None:
                                keyStatsKeyExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables","ips",ip2,analysis_stats_key)
                            
                                if keyStatsKeyExists == True:
                                    deMailerObservables["observables"]["ips"][ip2][analysis_stats_key].update(vtIPScanLastAnalysisStats)
                                elif keyStatsKeyExists == False:
                                    deMailerObservables["observables"]["ips"][ip2][analysis_stats_key]=vtIPScanLastAnalysisStats
                            
                            elif analysis_stats_key ==None:
                                deMailerObservables["observables"]["ips"][ip2].update(vtIPScanLastAnalysisStats)

                        except KeyError as e:
                            logging.error(f"[-] Function updateIPObservables() error :: {e}")

                    elif ip == ip2 and ip2 not in deMailerObservables["observables"]["ips"].keys() and ip in list(ipScanningResults):
                        # Retrieve the 'last_analysis_stats' from deMailerZeus after normalization
                        vtIPScanLastAnalysisStats = ipScanningResults[ip]["last_analysis_stats"]
                        try:
                            deMailerObservables["observables"]["ips"][ip2] = {}
                            if analysis_stats_key != None:
                                keyStatsKeyExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables","ips",ip2,analysis_stats_key)
                            
                                if keyStatsKeyExists ==True:    
                                    deMailerObservables["observables"]["ips"][ip2][analysis_stats_key].update(vtIPScanLastAnalysisStats)

                                if keyStatsKeyExists ==False:    
                                    deMailerObservables["observables"]["ips"][ip2].update({analysis_stats_key:vtIPScanLastAnalysisStats})
                                
                            elif keyStatsKeyExists ==None:
                                deMailerObservables["observables"]["ips"][ip2].update(vtIPScanLastAnalysisStats)
                        except KeyError as e:
                            logging.error(f"[-] Function updateIPObservables() error :: {e}")
   
    def updateDomainObservables(self,domains:list,deMailerZeus:dict,deMailerObservables:dict):
        """
        This function updates the 'domains' key inside '_deMailerObservables'. 
        Whatever you add inside this dict then is going to be printed in the 'Observables' table.
        
        Parameters
        ----------
        domains: list
            Key to update in the dictionary
        properties: dict
        
        Returns
        -------
        Doesn't return a value
        """

        if not isinstance(domains, list):
            raise AttributeError('updateDomainObservables() expects a list as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('updateDomainObservables() expects a dictionary as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('updateDomainObservables() expects a dictionary as third argument.')
        
        '''analysis_stats_key = None
        if service == "vt":
            analysis_stats_key = "last_analysis_stats"
        elif service == "opencti":
            analysis_stats_key = "opencti_analysis_stats"
        else:
            service = None'''
        
        # Check if 'observables' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables")
    
        #if keyExists:
        #    # Check if 'domains' key exists in the dictionary
        #    keyExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables","domains")
        #    if not keyExists:
        #        logging.error("[-] Can't update a the key 'domains' because doesn't exists in the _deMailerObservables dict.")
        
        if keyExists:
            # Check if 'domains' key exists in the dictionary
            keyTypeExists = self.deMailerZeusKeySearcher(deMailerObservables,"observables","domains")
            if not keyTypeExists:
                deMailerObservables["observables"].update({"domains":{}})
            
        else:
            deMailerObservables["observables"] = {}
            deMailerObservables["observables"].update({"domains":{}})

        # Retrieve a list of 'VirusTotalScans'
        keyExists = self.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans")
        domainScanningKeyList = None
        domainScanningResults = None
        if keyExists:
            firstLevelKeys = list(deMailerZeus["VirusTotalScans"])
            if len(firstLevelKeys) >0:
                # Returns 'domain_scanning' key in list format -> ['domain_scanning']
                domainScanningKeyList = [x for x in firstLevelKeys if x == "domain_scanning"]
                if len(domainScanningKeyList) >0:
                    # Convert to string
                    domainScanningKeyStr = domainScanningKeyList[0]
                    # Retrieve 'VirusTotalScans' results for IP scanning 
                    # {"VirusTotalScans": {"domain_scanning": { ...} }
                    domainScanningResults = deMailerZeus["VirusTotalScans"][domainScanningKeyStr]

        # Add Domain to observables dict if not exists
        self.addDomainObservables(domains)

        if len(deMailerZeus) >0 and len(domains) >0 and domainScanningKeyList != None:
            for domain in self._deMailerObservables["observables"]["domains"].keys():
                for domain2 in domains:
                    domain = domain.strip()
                    domain2 = domain2.strip()

                    if domain == domain2 and domain2 in deMailerObservables["observables"]["domains"].keys() and domain in list(domainScanningResults):
                        # Retrieve the 'last_analysis_stats' from deMailerZeus after normalization
                        vtDomainScanLastAnalysisStats = domainScanningResults[domain]["last_analysis_stats"]
                        try:
                            deMailerObservables["observables"]["domains"][domain].update({"last_analysis_stats":vtDomainScanLastAnalysisStats})
                        except KeyError as e:
                            logging.error(f"[-] Function updateDomainObservables() error :: {e}")

                    elif domain == domain2 and domain2 not in deMailerObservables["observables"]["domains"].keys():
                        # Retrieve the 'last_analysis_stats' from deMailerZeus after normalization
                        vtDomainScanLastAnalysisStats = domainScanningResults[domain]
                        try:
                            deMailerObservables["observables"]["domains"].update({domain:{"last_analysis_stats":vtDomainScanLastAnalysisStats}})
                        except KeyError as e:
                            logging.error(f"[-] Function updateDomainObservables() error :: {e}")
    
    def updateEmailObservables(self,emails:list,properties:dict):
        """
        This function updates the 'emails' key inside '_deMailerObservables'. 
        Whatever you add inside this dict then is going to be printed in the 'Observables' table.
        
        Parameters
        ----------
        emails: list
            Key to update in the dictionary
        properties: dict
        
        Returns
        -------
        Doesn't return a value
        """

        if not isinstance(properties, dict):
            raise AttributeError('updateDomainObservables() expects a dictionary as first argument.')
        
        # Check if 'observables' key exists in the dictionary
        keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables")
    
        if keyExists:
            # Check if 'emails' key exists in the dictionary
            keyExists = self.deMailerZeusKeySearcher(self._deMailerObservables,"observables","emails")
            if not keyExists:
                logging.error("[-] Can't update a the key 'emails' because doesn't exists in the _deMailerObservables dict.")
        

        if len(properties) >0 and len(emails) >0:
            
            for email in self._deMailerObservables["observables"]["emails"].keys():
                for email2 in emails:
                    email = email.strip()
                    email2 = email2.strip()
                    if email2 == email:
                        try:
                            self._deMailerObservables["observables"]["emails"][email].update(properties)
                        except KeyError as e:
                            logging.error(f"[-] Function updateEmailObservables() error :: {e}")