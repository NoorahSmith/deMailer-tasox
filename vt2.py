import ipaddress
import requests
import time
import ipaddress
import json
import pandas as pd
from termcolor import colored
from tabulate import tabulate
import base64
from datetime import timezone,datetime
import deviator
import validator
import logging
import observables
from fake_useragent import UserAgent

class VtEnrichment:

    def __init__(self, vt_api: str = None, extensive: bool =False) -> None:

        if vt_api !="" and vt_api !=None and not vt_api:
            raise ValueError('VT API Key missing')
        
        self.vt_api = vt_api
        self.extensive = extensive
        self.deviator = deviator.deMailerDeviator()
        self.validator = validator
        self.observables = observables.deMailerObservables()

        # Blacklist categories
        self.maliciousness = ["undetected","clean","harmless","type-unsupported","unrated"]

        #if vt_api != None:
        #    print(f"[+] You have provided a VirusTotal API. Scanning results are depending on the type of your API key (Personal/Entreprise).")
        #    print(f"[+] VirusTotal scanning has started ...")
    
    def randomUserAgent(self,enabled=True):
        
        fixedUserAgent = "{'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.36 Safari/535.7'}"
        headers = None
        try:
            ua = UserAgent().random
            headers = {"User-Agent":ua}
        except Exception as e:
            logging.error(f"[-] Error occured on function randomUserAgent()::{e}")
            logging.info(f"[*] The fixed User-Agent was used instead of the random: {ua}")

        if headers == None and not enabled:
            headers = {"User-Agent":fixedUserAgent}

        return headers
    
    def vtScanIPResultsUpdater(self,type:str,ip:str,engine:str,results,deMailerZeus:dict):
        """
        This function updates the core dictionary _deMailerZeus with VirusTotal results 
        """
        # Dictionary structure that holds VT scanning info -> {'Scanning': {'<IP>': {'engine': {'Sophos':{'result': 'malicious' ...}}}}}
        
        # Check if 'urls' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans")
    
        if keyExists:
            # Check if 'urls' key exists in the dictionary
            keyTypeExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type)
            if not keyTypeExists:
                deMailerZeus["VirusTotalScans"].update({type:{}})
            
        else:
            deMailerZeus["VirusTotalScans"] = {}
            deMailerZeus["VirusTotalScans"].update({type:{}})
        
        keyTypeExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type)
        keyIPExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type,ip)
        keyEngineExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type,ip,"last_analysis_results",engine)
        keyStatsExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type,ip,"last_analysis_stats")

        if keyTypeExists and not keyIPExists and not keyEngineExists and engine != "dummy":
            deMailerZeus["VirusTotalScans"][type].update({ip:{"last_analysis_results":{engine:{"result":results}}}})
        elif keyTypeExists and keyIPExists and not keyEngineExists and engine != "dummy":
            deMailerZeus["VirusTotalScans"][type][ip]["last_analysis_results"].update({engine:{"result":results}})
        elif keyTypeExists and keyIPExists and keyEngineExists and engine != "dummy":
            deMailerZeus["VirusTotalScans"][type][ip]["last_analysis_results"][engine].update({"result":results})
        
        if keyTypeExists and keyIPExists and not keyStatsExists and engine == "dummy":
            deMailerZeus["VirusTotalScans"][type][ip].update({"last_analysis_stats":results})
        elif keyTypeExists and not keyIPExists and not keyStatsExists and engine == "dummy":
            deMailerZeus["VirusTotalScans"][type].update({ip:{"last_analysis_stats":results}})
        
    def vtScanDomainResultsUpdater(self,type:str,domain:str,engine:str,results:str,deMailerZeus:dict):
        # Dictionary structure that holds VT scanning info -> {'Scanning': {'<Domain>': {'engine': {'Sophos':{'result': 'malicious' ...}}}}}
        
        # Check if 'urls' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans")
    
        if keyExists:
            # Check if 'urls' key exists in the dictionary
            keyTypeExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type)
            if not keyTypeExists:
                deMailerZeus["VirusTotalScans"].update({type:{}})
            
        else:
            deMailerZeus["VirusTotalScans"] = {}
            deMailerZeus["VirusTotalScans"].update({type:{}})
        
        keyTypeExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type)
        keyDomainExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type,domain)
        keyEngineExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type,domain,"last_analysis_results",engine)
        keyStatsExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type,domain,"last_analysis_stats")


        if keyTypeExists and not keyDomainExists and not keyEngineExists and engine != "dummy":
            deMailerZeus["VirusTotalScans"][type].update({domain:{"last_analysis_results":{engine:{"result":results}}}})
        elif keyTypeExists and keyDomainExists and not keyEngineExists and engine != "dummy":
            deMailerZeus["VirusTotalScans"][type][domain]["last_analysis_results"].update({engine:{"result":results}})
        elif keyTypeExists and keyDomainExists and keyEngineExists and engine != "dummy":
            deMailerZeus["VirusTotalScans"][type][domain]["last_analysis_results"][engine].update({"result":results})
        
        if keyTypeExists and keyDomainExists and not keyStatsExists and engine == "dummy":
            deMailerZeus["VirusTotalScans"][type][domain].update({"last_analysis_stats":results})
        elif keyTypeExists and not keyDomainExists and not keyStatsExists and engine == "dummy":
            deMailerZeus["VirusTotalScans"][type].update({domain:{"last_analysis_stats":results}})
    
    def vtScanUrlResultsUpdater(self,type:str,url:str,engine:str,results:str,deMailerZeus:dict):
        # Dictionary structure that holds VT scanning info -> {'Scanning': {'<Url>': {'engine': {'Sophos':{'result': 'malicious' ...}}}}}
        
        # Check if 'urls' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans")
    
        if keyExists:
            # Check if 'urls' key exists in the dictionary
            keyTypeExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type)
            if not keyTypeExists:
                deMailerZeus["VirusTotalScans"].update({type:{}})
            
        else:
            deMailerZeus["VirusTotalScans"] = {}
            deMailerZeus["VirusTotalScans"].update({type:{}})
        
        keyTypeExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type)
        keyUrlExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type,url)
        keyEngineExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type,url,"last_analysis_results",engine)
        keyStatsExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans",type,url,"last_analysis_stats")


        if keyTypeExists and not keyUrlExists and not keyEngineExists and engine != "dummy":
            deMailerZeus["VirusTotalScans"][type].update({url:{"last_analysis_results":{engine:{"result":results}}}})
        elif keyTypeExists and keyUrlExists and not keyEngineExists and engine != "dummy":
            deMailerZeus["VirusTotalScans"][type][url]["last_analysis_results"].update({engine:{"result":results}})
        elif keyTypeExists and keyUrlExists and keyEngineExists and engine != "dummy":
            deMailerZeus["VirusTotalScans"][type][url]["last_analysis_results"][engine].update({"result":results})
        
        if keyTypeExists and keyUrlExists and not keyStatsExists and engine == "dummy":
            deMailerZeus["VirusTotalScans"][type][url].update({"last_analysis_stats":results})
        elif keyTypeExists and not keyUrlExists and not keyStatsExists and engine == "dummy":
            deMailerZeus["VirusTotalScans"][type].update({url:{"last_analysis_stats":results}})

    def DEPRECATED_vtScanIPResultsUpdateObservables(self,ip:str,stats:dict,deMailerObservables:dict,service):
        """
        This function updates dictionary _deMailerObservables dict with VirusTotal scanning stats.

        Example: Response from VT
            ...
            last_analysis_stats": {
                "harmless": 69,
                "malicious": 1,
                "suspicious": 0,
                "undetected": 14,
                "timeout": 0
            }
            ...
        """

            
        try:
            if ip and ip != None:
                self.observables.updateIPObservables([ip],stats,deMailerObservables,service)
        except Exception as e:
            logging.error(f"[-] Couldn't update observables for IP {ip} with VirusTotal stats. Probably IP {ip} doesn't exists in _deMailerObservables.")
    
    def vtScanIPResultsUpdateObservablesV2(self,IP:str,deMailerZeus:dict,deMailerObservables:dict,service:str):
        """
        This function updates dictionary _deMailerObservables dict with VirusTotal scanning stats.
        It gets the results from deMailerZeus dictionary. 

        Arguments
        ---------
            IP: Takes an IP as string
            deMailerObservables: Observables dictionary
            deMailerZeus: It will use this dictionary to retrieve VT results for the provided IP
            service: Is a strings which holds the service name such as: VT, OpenCTI etc.

        Example: Response from VT
            ...
            last_analysis_stats": {
                "harmless": 69,
                "malicious": 1,
                "suspicious": 0,
                "undetected": 14,
                "timeout": 0
            }
            ...
        """

            
        try:
            if IP and IP != None:
                keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans")
                if keyExists:
                    self.observables.updateIPObservables([IP],deMailerZeus,deMailerObservables,service)
        except Exception as e:
            logging.error(f"[-] Couldn't update observables for IP {IP} with VirusTotal stats. Probably IP {IP} doesn't exists in _deMailerObservables.")
  
    def DEPRECATED_vtScanDomainResultsUpdateObservables(self,domain:str,stats:dict,deMailerObservables:dict):
        """
        This function updates dictionary _deMailerObservables dict with VirusTotal scanning stats.

        Example: Response from VT
            ...
            last_analysis_stats": {
                "harmless": 69,
                "malicious": 1,
                "suspicious": 0,
                "undetected": 14,
                "timeout": 0
            }
            ...
        """

        try:
            if domain and domain != None:
                self.observables.updateDomainObservables([domain],{"vt_last_analysis_stats":stats},deMailerObservables)
        except Exception as e:
            logging.error(f"[-] Couldn't update observables for Domain {domain} with VirusTotal stats. Probably Domain {domain} doesn't exists in _deMailerObservables.")
    
    def vtScanDomainResultsUpdateObservablesV2(self,domain:str,deMailerZeus:dict,deMailerObservables:dict):
        """
        This function updates dictionary _deMailerObservables dict with VirusTotal scanning stats.

        Example: Response from VT
            ...
            last_analysis_stats": {
                "harmless": 69,
                "malicious": 1,
                "suspicious": 0,
                "undetected": 14,
                "timeout": 0
            }
            ...
        """

        try:
            if domain and domain != None:
                keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"VirusTotalScans")
                if keyExists:
                    self.observables.updateDomainObservables([domain],deMailerZeus,deMailerObservables)
        except Exception as e:
            logging.error(f"[-] Couldn't update observables for Domain {domain} with VirusTotal stats. Probably Domain {domain} doesn't exists in _deMailerObservables.")
    
    def vtScanUrlResultsUpdateObservables(self,url:str,stats:dict,deMailerObservables:dict):
        """
        This function updates dictionary _deMailerObservables dict with VirusTotal scanning stats.

        Example: Response from VT
            ...
            last_analysis_stats": {
                "harmless": 69,
                "malicious": 1,
                "suspicious": 0,
                "undetected": 14,
                "timeout": 0
            }
            ...
        """

        try:
            if url and url != None:
                self.observables.updateUrlObservables([url],{"vt_last_analysis_stats":stats},deMailerObservables)
        except Exception as e:
            logging.error(f"[-] Couldn't update observables for URL {url} with VirusTotal stats. Probably URL {url} doesn't exists in _deMailerObservables.")

    def vtScanIP(self,ips:list,deMailerZeus:dict,deMailerObservables:dict):

        """
        Scans IPs and if the results are not clean then it will add a column 'vt_last_analysis_stats' to Observables dataframe. 
        The dataframe will be printed to screen by -> printObservables function. 

        This function doesn't belong to VirusTotal extensive scan.
        """
        if not isinstance(ips, list):
            raise AttributeError('vtScanIP() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanIP() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanIP() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        if len(ips)>0:
            for ip in ips:
                privateIP = self.validator.deMailerValidator(ip).isPrivate()
                if ip in self.deviator._deMailerDeviator["ipAddressWhitelisting"]:
                    isWhitelisted = True
                else:
                    isWhitelisted = False
                
                results_dict = ''
                if ip != None and privateIP == False and isWhitelisted == False:
                    time.sleep(3)
                    try:
                        ip_address = ipaddress.ip_address(ip).exploded
                        api_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
                        ip_color = colored(ip_address,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanIP() while scanning IP -> {ip} :: {e}")
        
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))
                
                attributes = None
                try:
                    attributes = results_dict["data"]["attributes"].items()
                    """
                    {"attributes": { "last_analysis_stats" :{ ... }, last_analysis_results:{"<ENGINE>":{ ... }}
                    """
                except Exception as e:
                    logging.error(f"Error occured on vtScanIP function -> last_analysis_results")
                
                #i=0
                last_analysis_stats = ""
                last_analysis_results = ""

                if attributes != None:
                    for attrKey,attrValue in attributes:
                        if attrKey == "last_analysis_stats":
                            last_analysis_stats = attrValue

                        if attrKey == "last_analysis_results":
                            last_analysis_results = attrValue

                else:
                    #print(f"    [-] No results!")
                    self.vtScanIPResultsUpdater("ip_scanning",ip,"No results","Clean",deMailerZeus)
                
                if last_analysis_results:
                    for engine,results in last_analysis_results.items():
                        for key,value in results.items():
                            if key == "result" and (value not in maliciousness):
                                result = value
                                #print(f'    [{i}] {engine} <-> {result}')
                                #i += 1
                                self.vtScanIPResultsUpdater("ip_scanning",ip,engine,result,deMailerZeus)#print("\n")

                # Update _deMailerZeus dict with 'last_analysis_stats' for every single IP
                # last_analysis_stats is result of total detections per IP.
                # In that case engine doens't exists and I need to create a dummy key 
                """
                Example: Response from VT
                ...
                last_analysis_stats": {
                    "harmless": 69,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0
                }
                ...
                """
                if last_analysis_stats and ip and ip !=None:
                    engine = "dummy"
                    try:
                        self.vtScanIPResultsUpdater("ip_scanning",ip,engine,last_analysis_stats,deMailerZeus)
                        #self.vtScanIPResultsUpdateObservables(ip,last_analysis_stats,deMailerObservables,"vt")
                        self.vtScanIPResultsUpdateObservablesV2(ip,deMailerZeus,deMailerObservables,"vt")
                    except Exception as e:
                        logging.error(f"[-] Error occured while updating data with VirusTotal 'last_analysis_stats' on vtScanIP() for IP {ip} :: {e}")
            
            #print(f"[+] VirusTotal scanning completed successfully for: {ips}")
    
    def vtScanIPResolutions(self,ips:list,deMailerZeus:dict,deMailerObservables:dict):

        if not isinstance(ips, list):
            raise AttributeError('vtScanIPResolutions() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanIPResolutions() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanIPResolutions() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        # if the list of IPs aren't empty and VirusTotal extensive scan is enabled then do scan.
        if len(ips)>0 and self.extensive:
            for ip in ips:
                privateIP = self.validator.deMailerValidator(ip).isPrivate()
                if ip in self.deviator._deMailerDeviator["ipAddressWhitelisting"]:
                    isWhitelisted = True
                else:
                    isWhitelisted = False
                
                results_dict = ''
                if ip != None and privateIP == False and isWhitelisted == False:
                    time.sleep(3)
                    try:
                        ip_address = ipaddress.ip_address(ip).exploded
                        api_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/resolutions'
                        ip_color = colored(ip_address,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanIPResolutions() while scanning IP -> {ip} :: {e}")
        
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))
                """
                Example: Response from VT
                ...
                ip_address_last_analysis_stats": {
                    "harmless": 69,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0
                }
                ...
                """
                # Resolution Scanning
                # Update _deMailerZeus dict with 'last_analysis_stats' for every single IP
                # last_analysis_stats is result of total detections per IP.
                # In that case engine doens't exists and I need to create a dummy key 
                
                attributes = None
                if results_dict and "data" in results_dict.keys():
                    if len(results_dict["data"]) > 0:
                        
                        ip_last_analysis_stats = ""
                        host_last_analysis_results = ""

                        try:
                            columns = pd.DataFrame(results_dict["data"]).columns.tolist()
                            attributes = pd.DataFrame(results_dict["data"],columns=columns).T.to_dict()
                            
                            if attributes != None and len(attributes) > 0:
                                for attrKey1, attrValue1 in attributes.items():
                                    for attrKey2,attrValue2 in attrValue1.items():
                                        for attrKey3,attrValue3 in attrValue2.items():
                                            if attrKey3 == "ip_address_last_analysis_stats":
                                                ip_last_analysis_stats = attrValue3

                                            if attrKey3 == "host_name_last_analysis_stats":
                                                host_last_analysis_results = attrValue3
                            else:
                                self.vtScanIPResultsUpdater("resolution",ip,"No results","Clean",deMailerZeus)            
                            
                        except Exception as e:
                            logging.error(f"[-] Error occured while updating data with VirusTotal stats on vtScanIPResolutions() for IP {ip} :: {e}")
                
                        
                        # Update _deMailerZeus dict with 'last_analysis_stats' for every single IP
                        # last_analysis_stats is result of total detections per IP.
                        # In that case engine doens't exists and I need to create a dummy key 
                        """
                        Example: Response from VT
                        ...
                        ip_address_last_analysis_stats": {
                            "harmless": 69,
                            "malicious": 1,
                            "suspicious": 0,
                            "undetected": 14,
                            "timeout": 0
                        }
                        ...
                        """
                        if ip_last_analysis_stats and ip and ip !=None:
                            engine = "dummy"
                            try:
                                self.vtScanIPResultsUpdater("resolution",ip,engine,attributes,deMailerZeus)
                                #self.vtScanIPResultsUpdateObservables(ip,attributes,deMailerObservables)
                                #self.vtScanIPResultsUpdateObservablesV2(ip,deMailerZeus,deMailerObservables,"vt")
                            except Exception as e:
                                logging.error(f"[-] Error occured while updating data with VirusTotal 'ip_last_analysis_stats' on vtScanIPResolutions() for IP {ip} :: {e}")
                   
            #print(f"[+] VirusTotal IP resolutions (Passive DNS Replication) scanning completed successfully for: {ips}")
    
    def vtScanIPCommunicatingFiles(self,ips:list,deMailerZeus:dict,deMailerObservables:dict):

        if not isinstance(ips, list):
            raise AttributeError('vtScanIPCommunicatingFiles() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanIPCommunicatingFiles() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanIPCommunicatingFiles() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        # if the list of IPs aren't empty and VirusTotal extensive scan is enabled then do scan.
        if len(ips)>0 and self.extensive:
            for ip in ips:
                privateIP = self.validator.deMailerValidator(ip).isPrivate()
                if ip in self.deviator._deMailerDeviator["ipAddressWhitelisting"]:
                    isWhitelisted = True
                else:
                    isWhitelisted = False
                
                results_dict = ''
                if ip != None and privateIP == False and isWhitelisted == False:
                    time.sleep(3)
                    try:
                        ip_address = ipaddress.ip_address(ip).exploded
                        api_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/communicating_files'
                        ip_color = colored(ip_address,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanIPCommunicatingFiles() while scanning IP -> {ip} :: {e}")
        
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))
                """
                Example: Response from VT
                ...
                last_analysis_stats": {
                    "harmless": 69,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0
                }
                ...
                """
                # Communicating Files Scanning
                # Update _deMailerZeus dict with 'last_analysis_stats' for every single IP
                # last_analysis_stats is result of total detections per IP.
                # In that case engine doens't exists and I need to create a dummy key 
                
                attributes = None
                if results_dict and "data" in results_dict.keys():
                    if len(results_dict["data"]) > 0:
                        
                        try:
                            columns = pd.DataFrame(results_dict["data"]).columns.tolist()
                            attributes = pd.DataFrame(results_dict["data"],columns=columns).T.to_dict()
                            engine = "dummy"
                            self.vtScanIPResultsUpdater("communicating_files",ip,engine,attributes,deMailerZeus)
                            self.vtScanIPResultsUpdateObservables(ip,attributes,deMailerObservables)
                        except Exception as e:
                            logging.error(f"[-] Error occured while updating data with VirusTotal stats on vtScanIPCommunicatingFiles() for IP {ip} :: {e}")
                
                    else:
                        #print(f"    [-] No results!")
                        self.vtScanIPResultsUpdater("communicating_files",ip,"No results","Clean",deMailerZeus)
                        #self.vtScanIPResultsUpdateObservables(ip,attributes,deMailerObservables)
                    #print("\n")
            
            #print(f"[+] VirusTotal IP communicating files scanning completed successfully for: {ips}")
    
    def vtScanIPReferrerFiles(self,ips:list,deMailerZeus:dict,deMailerObservables:dict):

        if not isinstance(ips, list):
            raise AttributeError('vtScanIPReferrerFiles() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanIPReferrerFiles() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanIPReferrerFiles() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        # if the list of IPs aren't empty and VirusTotal extensive scan is enabled then do scan.
        if len(ips)>0 and self.extensive:
            for ip in ips:
                privateIP = self.validator.deMailerValidator(ip).isPrivate()
                if ip in self.deviator._deMailerDeviator["ipAddressWhitelisting"]:
                    isWhitelisted = True
                else:
                    isWhitelisted = False
                
                results_dict = ''
                if ip != None and privateIP == False and isWhitelisted == False:
                    time.sleep(3)
                    try:
                        ip_address = ipaddress.ip_address(ip).exploded
                        api_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/referrer_files'
                        ip_color = colored(ip_address,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanIPReferrerFiles() while scanning IP -> {ip} :: {e}")
        
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))
                """
                Example: Response from VT
                ...
                last_analysis_stats": {
                    "harmless": 69,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0
                }
                ...
                """
                # Referrer Files Scanning
                # Update _deMailerZeus dict with 'last_analysis_stats' for every single IP
                # last_analysis_stats is result of total detections per IP.
                # In that case engine doens't exists and I need to create a dummy key 
                
                attributes = None
                if results_dict and "data" in results_dict.keys():
                    if len(results_dict["data"]) > 0:
                        
                        try:
                            columns = pd.DataFrame(results_dict["data"]).columns.tolist()
                            attributes = pd.DataFrame(results_dict["data"],columns=columns).T.to_dict()
                            engine = "dummy"
                            self.vtScanIPResultsUpdater("referrer_files",ip,engine,attributes,deMailerZeus)
                            #self.vtScanIPResultsUpdateObservables(ip,attributes,deMailerObservables)
                        except Exception as e:
                            logging.error(f"[-] Error occured while updating data with VirusTotal stats on vtScanIPReferrerFiles() for IP {ip} :: {e}")
                
                    else:
                        #print(f"    [-] No results!")
                        self.vtScanIPResultsUpdater("referrer_files",ip,"No results","Clean",deMailerZeus)
                        #self.vtScanIPResultsUpdateObservables(ip,attributes,deMailerObservables)
                #print("\n")
            
            #print(f"[+] VirusTotal IP referrer files scanning completed successfully for: {ips}")

    def vtScanDomain(self,domains:list,deMailerZeus:dict,deMailerObservables:dict):

        """
        This function doesn't belong to VirusTotal extensive scan.
        """
        if not isinstance(domains, list):
            raise AttributeError('vtScanDomain() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanDomain() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanDomain() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        if len(domains)>0:
            for domain in domains:
                
                # check if the Domain is whitelisted -> it returns True or False
                matched = self.deviator.matcher(self.deviator._deMailerDeviator["domainNameWhitelisting"],domain)
                
                if domain in self.deviator._deMailerDeviator["domainNameWhitelisting"] or matched:
                    isWhitelisted = True
                else:
                    isWhitelisted = False
                
                results_dict = ''

                if domain and domain != None and isWhitelisted == False:
                    time.sleep(3)
                    try:
                        api_url = f'https://www.virustotal.com/api/v3/domains/{domain}'
                        domain_color = colored(domain,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanDomain() while scanning Domain -> {domain} :: {e}")
        
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))
                
                attributes = None

                if results_dict:

                    try:
                        attributes = results_dict["data"]["attributes"].items()
                        """
                        {"attributes": { "last_analysis_stats" :{ ... }, last_analysis_results:{"<ENGINE>":{ ... }}
                        """
                    except Exception as e:
                        logging.error(f"Error occured on vtScanDomain function -> last_analysis_results")
                    #i=0
                    last_analysis_stats = ""
                    last_analysis_results = ""
                    
                    if attributes != None:
                        for attrKey,attrValue in attributes:
                            if attrKey == "last_analysis_stats":
                                last_analysis_stats = attrValue

                            if attrKey == "last_analysis_results":
                                last_analysis_results = attrValue
                    
                    if last_analysis_results:
                        for engine,results in last_analysis_results.items():
                            for key,value in results.items():
                                if key == "result" and (value not in maliciousness):
                                    result = value
                                    #print(f'    [{i}] {engine} <-> {result}')
                                    #i += 1
                                    self.vtScanDomainResultsUpdater("domain_scanning",domain,engine,result,deMailerZeus)

                    else:
                        #print(f"    [-] No results!")
                        self.vtScanDomainResultsUpdater("domain_scanning",domain,"No results","Clean",deMailerZeus)
                    #print("\n")

                    # Update _deMailerZeus dict with 'last_analysis_stats' for every single Domain
                    # last_analysis_stats is result of total detections per Domain.
                    # In that case engine doens't exists and I need to create a dummy key 
                    """
                    Example: Response from VT
                    ...
                    last_analysis_stats": {
                        "harmless": 69,
                        "malicious": 1,
                        "suspicious": 0,
                        "undetected": 14,
                        "timeout": 0
                    }
                    ...
                    """
                    if last_analysis_stats and domain and domain != None:
                        engine = "dummy"
                        try:
                            self.vtScanDomainResultsUpdater("domain_scanning",domain,engine,last_analysis_stats,deMailerZeus)
                            self.vtScanDomainResultsUpdateObservablesV2(domain,deMailerZeus,deMailerObservables)
                        except Exception as e:
                            logging.error(f"[-] Error occured while updating data with VirusTotal 'last_analysis_stats' on vtScanDomain() for Domain {domain} :: {e}")
                
            #print(f"[+] VirusTotal scanning completed successfully for: {domains}")

    def vtScanDomainResolutions(self,domains:list,deMailerZeus:dict,deMailerObservables:dict):

        if not isinstance(domains, list):
            raise AttributeError('vtScanDomainResolutions() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanDomainResolutions() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanDomainResolutions() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        # if the list of Domains aren't empty and VirusTotal extensive scan is enabled then do scan.
        if len(domains)>0 and self.extensive:
            for domain in domains:
                
                # check if the Domain is whitelisted -> it returns True or False
                matched = self.deviator.matcher(self.deviator._deMailerDeviator["domainNameWhitelisting"],domain)

                if domain in self.deviator._deMailerDeviator["domainNameWhitelisting"] or matched:
                    isWhitelisted = True
                else:
                    isWhitelisted = False

                results_dict = ''
                
                if domain and domain != None and isWhitelisted == False:
                    time.sleep(3)
                    try:
                        api_url = f'https://www.virustotal.com/api/v3/domains/{domain}/resolutions'
                        domain_color = colored(domain,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanDomainResolutions() while scanning Domain -> {domain} :: {e}")
        
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))
                """
                Example: Response from VT
                ...
                last_analysis_stats": {
                    "harmless": 69,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0
                }
                ...
                """
                # Resolution Scanning
                # Update _deMailerZeus dict with 'last_analysis_stats' for every single IP
                # last_analysis_stats is result of total detections per IP.
                # In that case engine doens't exists and I need to create a dummy key 
                
                attributes = None
                if results_dict and "data" in results_dict.keys():
                    if len(results_dict["data"]) > 0:
                        #attributes = pd.DataFrame(results_dict["data"]).to_dict()
                        try:
                            columns = pd.DataFrame(results_dict["data"]).columns.tolist()
                            attributes = pd.DataFrame(results_dict["data"],columns=columns).T.to_dict()
                            engine = "dummy"
                            self.vtScanDomainResultsUpdater("resolution",domain,engine,attributes,deMailerZeus)
                            #self.vtScanDomainResultsUpdateObservables(domain,attributes,deMailerObservables)
                        except Exception as e:
                            logging.error(f"[-] Error occured while updating data with VirusTotal stats on vtScanDomainResolutions() for Domain {domain} :: {e}")
                
                    else:
                        #print(f"    [-] No results!")
                        self.vtScanDomainResultsUpdater("resolution",domain,"No results","Clean",deMailerZeus)
                #print("\n")
            
            #print(f"[+] VirusTotal Domain resolutions (Passive DNS Replication) scanning completed successfully for: {domains}")
    
    def vtScanDomainCommunicatingFiles(self,domains:list,deMailerZeus:dict,deMailerObservables:dict):

        if not isinstance(domains, list):
            raise AttributeError('vtScanDomainCommunicatingFiles() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanDomainCommunicatingFiles() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanDomainCommunicatingFiles() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        # if the list of Domains aren't empty and VirusTotal extensive scan is enabled then do scan.
        if len(domains)>0 and self.extensive:
            for domain in domains:

                # check if the Domain is whitelisted -> it returns True or False
                matched = self.deviator.matcher(self.deviator._deMailerDeviator["domainNameWhitelisting"],domain)
                
                if domain in self.deviator._deMailerDeviator["domainNameWhitelisting"] or matched:
                    isWhitelisted = True
                else:
                    isWhitelisted = False
                
                results_dict = ''
                if domain and domain != None and isWhitelisted == False:
                    time.sleep(3)
                    try:
                        api_url = f'https://www.virustotal.com/api/v3/domains/{domain}/communicating_files'
                        domain_color = colored(domain,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanDomainCommunicatingFiles() while scanning Domain -> {domain} :: {e}")
        
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))
                """
                Example: Response from VT
                ...
                last_analysis_stats": {
                    "harmless": 69,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0
                }
                ...
                """
                #  Communicating Files Scanning
                # Update _deMailerZeus dict with 'last_analysis_stats' for every single IP
                # last_analysis_stats is result of total detections per IP.
                # In that case engine doens't exists and I need to create a dummy key 
                
                attributes = None
                if results_dict and "data" in results_dict.keys():
                    if len(results_dict["data"]) > 0:
                        try:
                            columns = pd.DataFrame(results_dict["data"]).columns.tolist()
                            attributes = pd.DataFrame(results_dict["data"],columns=columns).T.to_dict()
                            engine = "dummy"
                            self.vtScanDomainResultsUpdater("communicating_files",domain,engine,attributes,deMailerZeus)
                            #self.vtScanDomainResultsUpdateObservables(domain,attributes,deMailerObservables)
                        except Exception as e:
                            logging.error(f"[-] Error occured while updating data with VirusTotal stats on vtScanDomainCommunicatingFiles() for Domain {domain} :: {e}")
                
                    else:
                        #print(f"    [-] No results!")
                        self.vtScanDomainResultsUpdater("communicating_files",domain,"No results","Clean",deMailerZeus)
                    #print("\n")
            
            #print(f"[+] VirusTotal Domain Communicating files scanning completed successfully for: {domains}")
    
    def vtScanDomainReferrerFiles(self,domains:list,deMailerZeus:dict,deMailerObservables:dict):

        if not isinstance(domains, list):
            raise AttributeError('vtScanDomainReferrerFiles() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanDomainReferrerFiles() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanDomainReferrerFiles() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        # if the list of IPs aren't empty and VirusTotal extensive scan is enabled then do scan.
        if len(domains)>0 and self.extensive:
            for domain in domains:

                # check if the Domain is whitelisted -> it returns True or False
                matched = self.deviator.matcher(self.deviator._deMailerDeviator["domainNameWhitelisting"],domain)
                
                if domain in self.deviator._deMailerDeviator["domainNameWhitelisting"] or matched:
                    isWhitelisted = True
                else:
                    isWhitelisted = False
                
                results_dict = ''
                if domain and domain != None and isWhitelisted == False:
                    time.sleep(3)
                    try:
                        api_url = f'https://www.virustotal.com/api/v3/domains/{domain}/referrer_files'
                        domain_color = colored(domain,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanDomainReferrerFiles() while scanning Domain -> {domain} :: {e}")
        
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))
                """
                Example: Response from VT
                ...
                last_analysis_stats": {
                    "harmless": 69,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0
                }
                ...
                """
                #  Communicating Files Scanning
                # Update _deMailerZeus dict with 'last_analysis_stats' for every single IP
                # last_analysis_stats is result of total detections per IP.
                # In that case engine doens't exists and I need to create a dummy key 
                
                attributes = None
                if results_dict and "data" in results_dict.keys():
                    if len(results_dict["data"]) > 0:
                        try:
                            columns = pd.DataFrame(results_dict["data"]).columns.tolist()
                            attributes = pd.DataFrame(results_dict["data"],columns=columns).T.to_dict()
                            engine = "dummy"
                            self.vtScanDomainResultsUpdater("referrer_files",domain,engine,attributes,deMailerZeus)
                            #self.vtScanDomainResultsUpdateObservables(domain,attributes,deMailerObservables)
                        except Exception as e:
                            logging.error(f"[-] Error occured while updating data with VirusTotal stats on vtScanDomainReferrerFiles() for Domain {domain} :: {e}")
                
                    else:
                        #print(f"    [-] No results!")
                        self.vtScanDomainResultsUpdater("referrer_files",domain,"No results","Clean",deMailerZeus)
                #print("\n")
            
            #print(f"[+] VirusTotal Domain referrer files scanning completed successfully for: {domains}")

    def vtScanUrl(self,urls:list,deMailerZeus:dict,deMailerObservables:dict):

        if not isinstance(urls, list):
            raise AttributeError('vtScanUrl() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanUrl() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanUrl() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        if len(urls)>0:
            for url in urls:
                if url in self.deviator._deMailerDeviator["UrlWhitelisting"]:
                    isWhitelisted = True
                else:
                    isWhitelisted = False
                
                if url and url != None and isWhitelisted == False:
                    # Convert Url -> base64
                    url2b64 = base64.urlsafe_b64encode(f"{url}".encode()).decode().strip("=")
                    results_dict = ''
                    time.sleep(3)
                    try:
                        api_url = f'https://www.virustotal.com/api/v3/urls/{url2b64}'
                        url_color = colored(url,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanUrl() while scanning Url -> {url} :: {e}")
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))

                # Decode Base64 Url and fix padding error mesage
                # https://stackoverflow.com/questions/53843023/how-to-avoid-incorrect-padding-error-while-base64-decoding-this-string-in-pyth
                #for i in url2b64.split("."):
                #    print(base64.b64decode(i + '=' * (-len(i) % 4)))
                
                attributes = None
                if results_dict and "data" in results_dict.keys(): 
                    try:
                        attributes = results_dict["data"]["attributes"].items()
                        """
                        {"attributes": { "last_analysis_stats" :{ ... }, last_analysis_results:{"<ENGINE>":{ ... }}
                        """
                    except Exception as e:
                        logging.error(f"Error occured on vtScanUrl function -> last_analysis_results")
                #i=0
                last_analysis_stats = ""
                last_analysis_results = ""
                malicious = 0
                harmless = 0
                suspicious = 0 
                undetected = 0 
                if attributes != None:
                    for attrKey,attrValue in attributes:
                        if attrKey == "last_analysis_stats":
                            last_analysis_stats = attrValue
                            malicious = attrValue["malicious"]
                            harmless = attrValue["harmless"]
                            suspicious = attrValue["suspicious"] 
                            undetected = attrValue["undetected"]

                        if attrKey == "last_analysis_results":
                            last_analysis_results = attrValue
                
                if last_analysis_results:
                    for engine,results in last_analysis_results.items():
                        for key,value in results.items():
                            if key == "result" and (value not in maliciousness):
                                result = value
                                #print(f'    [{i}] {engine} <-> {result}')
                                #i += 1
                                self.vtScanUrlResultsUpdater("Scanning",url,engine,result,deMailerZeus)

                else:
                    #print(f"    [-] No results!")
                    self.vtScanUrlResultsUpdater("Scanning",url,"No results","Clean",deMailerZeus)
                #print("\n")

                # Update _deMailerZeus dict with 'last_analysis_stats' for every single Url
                # last_analysis_stats is result of total detections per Url.
                # In that case engine doens't exists and I need to create a dummy key 
                """
                Example: Response from VT
                ...
                last_analysis_stats": {
                    "harmless": 69,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0
                }
                ...
                """
                if last_analysis_stats and url and url != None:
                    engine = "dummy"
                    try:
                        self.vtScanUrlResultsUpdater("Scanning",url,engine,last_analysis_stats,deMailerZeus)
                        self.vtScanUrlResultsUpdateObservables(url,last_analysis_stats,deMailerObservables)
                    except Exception as e:
                        logging.error(f"[-] Error occured while updating data with VirusTotal 'last_analysis_stats' on vtScanUrl() for Url {url} :: {e}")
            
            #print(f"[+] VirusTotal scanning completed successfully for: {urls}")

    def vtScanUrlCommunicatingFiles(self,urls:list,deMailerZeus:dict,deMailerObservables:dict):

        if not isinstance(urls, list):
            raise AttributeError('vtScanUrlCommunicatingFiles() expects string as first argument.')
        if not isinstance(deMailerZeus, dict):
            raise AttributeError('vtScanUrlCommunicatingFiles() expects dict as second argument.')
        if not isinstance(deMailerObservables, dict):
            raise AttributeError('vtScanUrlCommunicatingFiles() expects dict as third argument.')
        
        # Blacklist categories
        maliciousness = self.maliciousness

        # if the list of URls aren't empty and VirusTotal extensive scan is enabled then do scan.
        if len(urls)>0 and self.extensive:
            for url in urls:

                if url in self.deviator._deMailerDeviator["UrlWhitelisting"]:
                    isWhitelisted = True
                else:
                    isWhitelisted = False
                
                results_dict = ''
                if url and url != None and isWhitelisted == False:
                    # Convert Url -> base64
                    url2b64 = base64.urlsafe_b64encode(f"{url}".encode()).decode().strip("=")
                    
                    time.sleep(3)
                    try:
                        api_url = f'https://www.virustotal.com/api/v3/urls/{url2b64}/communicating_files'
                        url_color = colored(url,"green")

                        userAgent = self.randomUserAgent()
                        headers = {'x-apikey':f'{self.vt_api}'}
                        headers.update(userAgent)
                        response = requests.get(api_url, headers=headers)
                        results_dict = json.loads(response.content)
                        
                    except ValueError as e:
                        logging.error(f"Function error vtScanUrlCommunicatingFiles() while scanning Url -> {url} :: {e}")
        
        
                # Pretty Printing JSON string back
                #print(json.dumps(results_dict, indent = 4, sort_keys=True))
                """
                Example: Response from VT
                ...
                last_analysis_stats": {
                    "harmless": 69,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0
                }
                ...
                """
                #  URL Communicating Files Scanning
                # Update _deMailerZeus dict with 'last_analysis_stats' for every single IP
                # last_analysis_stats is result of total detections per IP.
                # In that case engine doens't exists and I need to create a dummy key 
                
                attributes = None
                if results_dict and "data" in results_dict.keys():
                    if len(results_dict["data"]) > 0:
                        try:
                            columns = pd.DataFrame(results_dict["data"]).columns.tolist()
                            attributes = pd.DataFrame(results_dict["data"],columns=columns).T.to_dict()
                            engine = "dummy"
                            self.vtScanUrlResultsUpdater("communicating_files",url,engine,attributes,deMailerZeus)
                            self.vtScanUrlResultsUpdateObservables(url,attributes,deMailerObservables)
                        except Exception as e:
                            logging.error(f"[-] Error occured while updating data with VirusTotal stats on vtScanDomainCommunicatingFiles() for Url {url} :: {e}")
                
                    else:
                        #print(f"    [-] No results!")
                        self.vtScanUrlResultsUpdater("communicating_files",url,"No results","Clean",deMailerZeus)
                    #print("\n")
            
            #print(f"[+] VirusTotal Url Communicating files scanning completed successfully for: {urls}")