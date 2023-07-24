from lib import *
import __banner__

from converter import deMailerMsg2EmlConverter,deMailerBodyConverter,deMailerMiscConverter
import deviator
from observables import *
import extractor
import checks
import mailroute
import printerpd
import geoip
import dnslookup
import observables
import who_is
import json
import vt2
from mapping import *
import colors
import yarascanner
import deMailer_global_vars

WHITELISTED_IPS = None
WHITELISTED_DOMAINS = None
WHITELISTED_EMAILS = None

class deMailerCore:

    def __init__(self):

        self.ips = []
        self.domain_list = {}

        self._deMailerZeus = deMailerMapping()
        self.extractor = extractor.deMailerExtractor()
        self.updater = extractor.deMailerExtractorUpdater()
        self.observables = observables.deMailerObservables()
        self.deviator = deviator.deMailerDeviator(whitelisted_ips=WHITELISTED_IPS,whitelisted_domains=WHITELISTED_DOMAINS,whitelisted_emails=WHITELISTED_EMAILS)
        self.mailrouting = mailroute.deMailerMailRouting()
        self.printerpd = printerpd.deMailerPrinter(deMailer_global_vars.global_variable.TABULATE_TABLE_FORMAT)
        self.geoip = geoip.deMailerGeoIP()
        self.dnslookup = dnslookup.deMailerDNS()
        self.whoislookup = who_is.deMailerWhoIs()
        self.checks = checks.deMailerChecks()
        self._checkResults = self.checks._checkResults
        self.colors = colors.style()
        self.yarascanner = yarascanner.deMailerYaraScanner()

        self.NotExist = "Doesn't Exist"
    
    def saveToFile(self,f: str,JSONcontents):
        # Get current directory
        cwd = os.getcwd()
        # Get the path and not the filename
        fNamePath = Path(f).parent
        # Get only the filename
        fName = Path(f).name
        # Concat file path and file name to get the full-file-name
        fileFullPath = str(fNamePath) + '/' +fName
        try:
            # Make the directory if not exist
            makeDir = os.makedirs(fNamePath, exist_ok=True)
        except PermissionError as e:
            raise Exception(f"{self.colors.RED}[-] Failed to create path {str(fNamePath)}. Check the name of the provided path :: {e}")
        
        with open(fileFullPath, 'w+') as outfile:
            try:
                deMailerResults=json.dumps(JSONcontents,indent=2,default=str)
                outfile.write(deMailerResults)
                outfile.close()
                print(f"{self.colors.GREEN}[+] JSON successfully saved to: {fileFullPath} {self.colors.RESET}")
            except Exception as e:
                logging.error(f"{self.colors.RED}[-] Couldn't write JSON results to file :: {e}{self.colors.RESET}")
                   

    def deMailerRunner(self,file: str):

        emailFullFilePathToLower = deMailerMiscConverter(file).strToLowerCase()

        if emailFullFilePathToLower.endswith(".msg"):
            
            try:
                # Convert MSG -> EML and return the path of the EML
                email = deMailerMsg2EmlConverter().convertMSGtoEMLv2(emailFullFilePathToLower)
                print(f"{self.colors.GREEN}[+] MSG converted to EML succcessfully{self.colors.RESET}")
            except Exception as e:
                raise Exception(f"{self.colors.RED}[[-] Failed to convert the MSG to EML{self.colors.RESET}")
        else:
            # Holds the EML file path
            email = file
        
        try:
            # Retrieve all the headers and their values from the e-mail
            _emailHeaders = self.extractor.extractHeadersV2(email)
            print("[+] Extracting headers ...")
        except Exception as e:
            raise Exception(f"{self.colors.RED}[-] Failed to retrieve extract headers from the e-mail{self.colors.RESET}")

        for headerKey, headerValue in _emailHeaders.items():
            
            if headerKey.lower() in ['received','authentication-results']:
                # Extract e-mail from smtp.from
                smtpFrom = self.extractor.extractEmailSmtpFrom(headerValue)
                # Update '_deMailerZeus' dict
                if not smtpFrom or smtpFrom == '' or smtpFrom == None:
                    self.updater.updateEmailSmtpFrom(self.NotExist,self._deMailerZeus)
                else:
                    self.updater.updateEmailSmtpFrom(smtpFrom,self._deMailerZeus)
                
                # Extract e-mail from Envelop-From
                envelopFrom = self.extractor.extractEmailEnvelopeFrom(headerValue)
                # Update '_deMailerZeus' dict
                if not envelopFrom or envelopFrom == '' or envelopFrom == None:
                    self.updater.updateEmailEnvelopFrom(self.NotExist,self._deMailerZeus)
                else:
                    self.updater.updateEmailEnvelopFrom(envelopFrom,self._deMailerZeus)

                # Extract e-mail from header.from
                envelopFrom = self.extractor.extractEmailHeaderFrom(headerValue)
                # Update '_deMailerZeus' dict
                if not headerFrom or headerFrom == '' or headerFrom == None:
                    self.updater.updateEmailHeaderFrom(self.NotExist,self._deMailerZeus)
                else:
                    self.updater.updateEmailHeaderFrom(headerFrom,self._deMailerZeus)
                
            if headerKey.lower() == 'from':
                # Extract e-mail from From
                emailFrom = self.extractor.extractEmail(headerValue)
                # Update '_deMailerZeus' dict
                self.updater.updateEmailFrom(emailFrom,self._deMailerZeus)
        
            if headerKey.lower() == 'to':
                # Extract e-mail from To
                emailTo = self.extractor.extractEmail(headerValue)
                # Update '_deMailerZeus' dict
                self.updater.updateEmailTo(emailTo,self._deMailerZeus)
                # Whitelist Recipients
                if len(emailTo) >0 :
                    self.deviator.updateEmailDeviator(list(emailTo))
                
            if headerKey.lower() == 'cc':
                # Extract e-mail from Cc
                emailCc = self.extractor.extractEmail(headerValue)
                # Update '_deMailerZeus' dict
                self.updater.updateEmailCc(emailCc,self._deMailerZeus)
            
            if headerKey.lower() == 'bcc':
                # Extract e-mail from Cc
                emailBcc = self.extractor.extractEmail(headerValue)
                # Update '_deMailerZeus' dict
                self.updater.updateEmailBcc(emailBcc,self._deMailerZeus)
            
            if headerKey.lower() == 'return-path':
                # Extract e-mail from Return-Path -> list
                emailReturnPath = self.extractor.extractEmail(headerValue)
                # Update '_deMailerZeus' dict
                if not emailReturnPath or emailReturnPath == '' or emailReturnPath == None:
                    self.updater.updateEmailReturnPath(self.NotExist,self._deMailerZeus)
                else:
                    self.updater.updateEmailReturnPath(emailReturnPath,self._deMailerZeus)
            else:
                    self.updater.updateEmailReturnPath([self.NotExist],self._deMailerZeus)

            if headerKey.lower() == 'reply-to':
                # Extract e-mail from Reply-To -> list
                emailReplyTo = self.extractor.extractEmail(headerValue)
                # Update '_deMailerZeus' dict
                if not emailReplyTo or emailReplyTo == '' or emailReplyTo == None:
                    self.updater.updateEmailReplyTo(self.NotExist,self._deMailerZeus)
                else:
                    self.updater.updateEmailReplyTo(emailReplyTo,self._deMailerZeus)
            else:
                self.updater.updateEmailReplyTo([self.NotExist],self._deMailerZeus)
                
            if headerKey.lower() == 'message-id':
                # Extract e-mail from Message-ID
                emailMessageID = self.extractor.extractEmail(headerValue)
                # Update '_deMailerZeus' dict
                self.updater.updateEmailMessageID(emailMessageID,self._deMailerZeus)

            if headerKey.lower() == 'dkim-signature':

                # Extract from DKIM-Signature -> d (Domain) and s (Selector)
                DKIM_Domain = self.extractor.extractDKIMdomain(headerValue)
                DKIM_Selector = self.extractor.extractDKIMselector(headerValue)
                
                # Extract e-mail from From
                From = _emailHeaders.get('From')
                From = self.extractor.extractEmail(From)

                # Update '_deMailerZeus' dict
                if DKIM_Domain and DKIM_Domain != None and DKIM_Selector and DKIM_Selector != None:
                    dkimSelectorDomain = f"{DKIM_Selector}._domainkey.{DKIM_Domain}"
                    self.updater.updateEmailDKIMLookUP(dkimSelectorDomain,self._deMailerZeus)
                    self.checks.checkDKIMLookUP(DKIM_Domain,DKIM_Selector)
                    self.checks.checkDKIMVerifier(email)

                if DKIM_Domain and DKIM_Domain != None and len(From) > 0:
                    self.checks.checkFromWithDKIMdomain(From,list(DKIM_Domain.lower().split()))
                
            if headerKey.lower() == 'authentication-results':

                # Extract from Authentication-Results -> dkim=pass header.i=@<DOMAIN> header.s=<SELECTOR>
                #print(headerValue)
                DKIM_verification_result = self.extractor.extractDKIMValidation(headerValue)
                DKIM_Domain = self.extractor.extractDKIMAuthenticationResultsheaderDomain(headerValue)
                DKIM_Selector = self.extractor.extractDKIMAuthenticationResultsheaderSelector(headerValue)
                DMARC_Domain = self.extractor.extractEmailHeaderFrom(headerValue)
                SPF_Domain = self.extractor.extractEmailSmtpFrom(headerValue)

                # Extract SPF authentication results from 'Authentication-Results'
                SPF_authentication_results = self.extractor.extractSPFValidation(headerValue)
                
                # Check verification
                if DKIM_Domain and DKIM_Domain != None and DKIM_Selector and DKIM_Selector != None and DKIM_verification_result and DKIM_verification_result !=None:
                    self.checks.checkDKIMAuthenticationResults(DKIM_Domain,DKIM_Selector,DKIM_verification_result)
                
                if SPF_authentication_results and SPF_authentication_results != None:
                    self.checks.checkSPFvalidation(SPF_authentication_results,headerValue)
                
                # DMARC Lookup
                # Only sender's domain needed from Authentication-Results. It's the same with DKIM domain
                if DMARC_Domain and DMARC_Domain != None:
                    self.checks.checkDMARCLookUP(DMARC_Domain)
                
                # DMARC verifier
                # Extract the domain from smtp.from which is has email format
                SPF_d = self.extractor.extractDomain(SPF_Domain)
                # if there are results
                if len(SPF_d) >0:
                    # convert list -> string
                    SPF_d = ''.join(SPF_d)
                # if no results, return the value of extracted SPF_Domain variable
                else:
                    SPF_d = SPF_Domain
                
                # Extract the domain from DKIM value which probably is an email format: @google.com
                DKIM_d = self.extractor.extractDomain(DKIM_Domain)
                # if there are results
                if len(DKIM_d) >0:
                    # convert list -> string
                    DKIM_d = ''.join(DKIM_d)
                # if no results, return the value of extracted SPF_Domain variable
                else:
                    DKIM_d = DKIM_Domain

                if DMARC_Domain:
                    self.checks.checkDMARCVerifier(DKIM_d,SPF_d,DMARC_Domain)
            
            # Extract the value from 'Received: from'
            # ==== Initialize Routing ====
            if headerKey.lower() == 'received' and (headerValue.lower().startswith("from") or headerValue.lower().startswith("by")):
                _routingTable = self.mailrouting.mailRoute(headerValue)
                self.updater.updateRoutingTable(_routingTable,self._deMailerZeus)

            # === Extract IPs and Emails from ALL the headers ==== #
            self.extractor.extractIPv4(headerValue)
            self.extractor.extractIPv6(headerValue)
            self.extractor.extractEmail(headerValue)
            self.extractor.extractDomain(headerValue)

            # Extract domain from header.from
            headerFrom = self.extractor.extractEmailHeaderFrom(headerValue)
            # Update '_deMailerZeus' dict
            self.updater.updateEmailHeaderFrom(headerFrom,self._deMailerZeus)

        try:    
            # Extract the payload (Body) from the email
            # Function returns a list
            payloads = self.extractor.extractPayload(email)
            emailBody = ""
            if len(payloads)>0:
                for p in payloads:
                    if type(p) != str:
                        for payload in p.walk():
                            emailBody += str(payload)
                    else:
                        emailBody += p
        except Exception as e:
            logging.error(f"{colors.style.RED}[-] Function deMailerRunner() raised an error while extracting the payload from the e-mail :: {e}{colors.style.RESET}")
        
        # Extract email body and attachments
        # Converts body -> txt
        try:
            if email:
                self.extractor.extractBody(email)
        except Exception as e:
            logging.error(f"{colors.style.RED}[-] Function extractBody() raised error :: {e}{colors.style.RESET}")
        
        # Extract all Urls,IPs,Emails from email Body
        if emailBody:
            self.extractor.extractURLs(emailBody)
            self.extractor.extractIPv4(emailBody)
            self.extractor.extractIPv6(emailBody)
            self.extractor.extractEmail(emailBody)
            self.extractor.extractDomain(emailBody)
        
        Urls = self.extractor.urls
        IPv4 = self.extractor.allIPv4s
        IPv6 = self.extractor.allIPv6s
        Emails = self.extractor.emails
        Domains = self.extractor.domains

        # Adding a list of Urls,IPs,Emails to dict '_deMailerObservables' and returns the 'urls' key -> values
        if len(Urls) > 0:
            _urlObservables = self.observables.addUrlObservables(Urls)
        if len(IPv4) > 0:
            _ipObservables = self.observables.addIPObservables(IPv4)
        if len(IPv6) > 0:
            _ipObservables = self.observables.addIPObservables(IPv6)
        if len(Emails) > 0:
            _emailObservables = self.observables.addEmailObservables(Emails)
        if len(Domains) > 0:
            _domainObservables = self.observables.addDomainObservables(Domains)
        
        # ==== Checking Headers ===== #
        self.checks.checkFromWithReturnPathResults(self._deMailerZeus["emails"])
        self.checks.checkFromWithEnvelopFromResults(self._deMailerZeus["emails"])
        self.checks.checkFromWithSmtpFromResults(self._deMailerZeus["emails"])
        self.checks.checkFromWithMessageIDResults(self._deMailerZeus["emails"])
        self.checks.checkFromWithReplyToResults(self._deMailerZeus["emails"])
        
        
        # ==== Initialize Footprints ====
        self.updater.updateFootprints(_emailHeaders,self._deMailerZeus,self._checkResults)

        # ==== Print Email Route ==== #
        try:
            self.printerpd.printMailRoute(self._deMailerZeus["routingTable"],self.scanmode)
        except KeyError as e:
            logging.error(f"{colors.style.YELLOW}[-] Key 'routingTable' not found in '_deMailerZeus' dict :: {e}{colors.style.RESET}")
        
        # ==== Print Footprints ==== #
        try:
            self.printerpd.printFootprints(self._deMailerZeus["footprints"],self.scanmode)
        except KeyError as e:
            logging.error(f"{colors.style.YELLOW}[-] Key 'footprints' not found in '_deMailerZeus' dict :: {e}{colors.style.RESET}")
        
        # ==== Print Emails ==== #
        try:
            self.printerpd.printEmails(self.observables._deMailerObservables["observables"]["emails"],self.scanmode)
        except KeyError as e:
            logging.info(f"{colors.style.YELLOW}[-] Email addresses not found!{colors.style.RESET}")
            logging.info(f"{colors.style.YELLOW}[-] Key 'emails' not found in '_deMailerObservables' dict :: {e}{colors.style.RESET}")
        
        # ==== Print Urls ==== #
        try:
            self.printerpd.printUrls(self.observables._deMailerObservables["observables"]["urls"],self.scanmode)
        except KeyError as e:
            logging.info(f"{colors.style.YELLOW}[-] Urls not found!{colors.style.RESET}")
            logging.info(f"{colors.style.YELLOW}[-] The key 'url' not found in '_deMailerObservables' dict :: {e}{colors.style.RESET}")
        
        # ==== Initialize/Print GeoIP ====
        allIPs = []
        allIPs.extend(IPv4)
        allIPs.extend(IPv6)
        _geoIP = self.geoip.GeoIpLookUp(allIPs)
        self.updater.updateGeoIP(_geoIP,self._deMailerZeus)
        self.printerpd.printGeoIP(self._deMailerZeus["geoIPLookUp"],self.scanmode)

        # ==== Initialize/Print DNS LookUP ====
        _dnsLookUp = self.dnslookup.lookupDNS(Domains)
        self.updater.updateDnsLookUp(_dnsLookUp,self._deMailerZeus)
        self.printerpd.printDnsLookUp(self._deMailerZeus["dnsLookUp"],self.scanmode)

        # ==== Initialize/Print WhoIs ====
        _whoisLookUpDomains = self.whoislookup.domainWhois(Domains)
        _whoisLookUpIPs = self.whoislookup.ipWhois(allIPs)
        self.updater.updateWhoisLookUp(_whoisLookUpDomains,self._deMailerZeus)
        self.updater.updateWhoisLookUp(_whoisLookUpIPs,self._deMailerZeus)
        self.printerpd.printWhoIsLookUp(self._deMailerZeus["whoIsLookUp"],self.scanmode)
        
        # ==== Print Header Checks ====
        self.printerpd.printHeaderChecks(self._checkResults,self.scanmode)

        # ==== Update Observables and add a column to 'Observables' table ====
        if len(allIPs) > 0:
            self.observables.updateIPObservablesFromZeus(allIPs,self._deMailerZeus["geoIPLookUp"],"IsPrivate","IsWhitelisted")
            self.observables.updateIPObservables(allIPs,{"Datasource":"IP"},self.observables._deMailerObservables,None)
            
            # VirusTotal scanning
            if self.vt_api != None:
                #print(f"[+] VirusTotal IP Scanning: {self.colors.GREEN}{allIPs}{self.colors.RESET}")
                vt2.VtEnrichment(self.vt_api,self.vt_extensive).vtScanIP(allIPs,self._deMailerZeus,self.observables._deMailerObservables)
                #self.printerpd.printVTRelations(self.observables._deMailerObservables["observables"],'ips')
                #print("\n")

            if self.vt_api != None and self.vt_extensive:
                print(f" >[*] VirusTotal IP Relations - Referrer Files: {self.colors.GREEN}{allIPs}{self.colors.RESET}")
                vt2.VtEnrichment(self.vt_api,self.vt_extensive).vtScanIPReferrerFiles(allIPs,self._deMailerZeus,self.observables._deMailerObservables)
                self.printerpd.printVTRelations(self._deMailerZeus["VirusTotalScans"],'referrer_files')
                print("\n")
                
                print(f" >[*] VirusTotal IP Relations - Passive DNS Replication: {self.colors.GREEN}{allIPs}{self.colors.RESET}")
                vt2.VtEnrichment(self.vt_api,self.vt_extensive).vtScanIPResolutions(allIPs,self._deMailerZeus,self.observables._deMailerObservables)
                self.printerpd.printVTRelations(self._deMailerZeus["VirusTotalScans"],'resolution')
                print("\n")
                
                print(f" >[*] VirusTotal IP Relations - Communicating Files:{self.colors.GREEN}{allIPs}{self.colors.RESET}")
                vt2.VtEnrichment(self.vt_api,self.vt_extensive).vtScanIPCommunicatingFiles(allIPs,self._deMailerZeus,self.observables._deMailerObservables)
                self.printerpd.printVTRelations(self._deMailerZeus["VirusTotalScans"],'communicating_files')
                print("\n")


        if len(Domains) > 0:
            self.observables.updateDomainObservablesFromZeus(Domains,self._deMailerZeus["dnsLookUp"],"IsWhitelisted")
            self.observables.updateDomainObservables(Domains,{"Datasource":"Domain"},self.observables._deMailerObservables)

            # VirusTotal scanning
            if self.vt_api != None:
                #print(f"[+] VirusTotal Domain Scanning: {self.colors.GREEN}{Domains}{self.colors.RESET}")
                vt2.VtEnrichment(self.vt_api,self.vt_extensive).vtScanDomain(Domains,self._deMailerZeus,self.observables._deMailerObservables)
                #self.printerpd.printVTRelations(self.observables._deMailerObservables["observables"],'domains')
                #print("\n")

            if self.vt_api != None and self.vt_extensive:
                print(f"[*] VirusTotal Domain Relations - Referrer Files: {self.colors.GREEN}{Domains}{self.colors.RESET}")
                vt2.VtEnrichment(self.vt_api,self.vt_extensive).vtScanDomainReferrerFiles(Domains,self._deMailerZeus,self.observables._deMailerObservables)
                self.printerpd.printVTRelations(self._deMailerZeus["VirusTotalScans"],'referrer_files')
                print("\n")

                print(f"[*] VirusTotal Domain Relations - Resolutions: {self.colors.GREEN}{Domains}{self.colors.RESET}")
                vt2.VtEnrichment(self.vt_api,self.vt_extensive).vtScanDomainResolutions(Domains,self._deMailerZeus,self.observables._deMailerObservables)
                self.printerpd.printVTRelations(self._deMailerZeus["VirusTotalScans"],'resolution')
                print("\n")
            
                print(f"[*] VirusTotal Domain Relations - Communicating Files: {self.colors.GREEN}{Domains}{self.colors.RESET}")
                vt2.VtEnrichment(self.vt_api,self.vt_extensive).vtScanDomainCommunicatingFiles(Domains,self._deMailerZeus,self.observables._deMailerObservables)
                self.printerpd.printVTRelations(self._deMailerZeus["VirusTotalScans"],'communicating_files')
                print("\n")
        
        if len(Emails) > 0:
            self.observables.updateEmailObservablesFromDeviator(Emails,self.deviator._deMailerDeviator,"IsWhitelisted")
            self.observables.updateEmailObservables(Emails,{"Datasource":"Email"})

        if len(Urls) > 0:
            self.observables.updateUrlObservablesFromDeviator(Urls,self.deviator._deMailerDeviator,"IsWhitelisted")
            self.observables.updateUrlObservables(Urls,{"Datasource":"Url"},self.observables._deMailerObservables)

            # VirusTotal scanning
            #if self.vt_api != None:
                #print(f"[+] VirusTotal URL Scanning: {Urls}")
                #vt2.VtEnrichment(self.vt_api).vtScanUrl(Urls,self._deMailerZeus,self.observables._deMailerObservables)
                #self.printerpd.printVTRelations(self.observables._deMailerObservables["observables"],'urls')

                #print(f"[*] Domain Relations - Communicating Files: {Urls}")
            #    vt2.VtEnrichment(self.vt_api).vtScanUrlCommunicatingFiles(Urls,self._deMailerZeus,self.observables._deMailerObservables)
                #self.printerpd.printVTRelations(self.observables._deMailerObservables["observables"],'urls')
                

        # ==== Print Observables ====
        self.printerpd.printObservables(self.observables._deMailerObservables["observables"],self.scanmode)
        #self.printerpd.printVTRelations(self.observables._deMailerObservables["observables"],'domains')
        #self.printerpd.printVTRelations(self.observables._deMailerObservables["observables"],'ips')
        #self.printerpd.printVTRelations(self.observables._deMailerObservables["observables"],'urls')

        #print("+++++++++++++++++++++++++++++")
        #print(self._deMailerZeus["emails"])
        #dataInJSON = json.dumps(self._deMailerZeus,indent=2,default=str)
        #print(dataInJSON)
        #f = open('deMailerZeus.json','w')
        #f.write(dataInJSON)
        #f.close()
        
        #print(self.observables._deMailerObservables)
        dataInJSON = json.dumps(self._checkResults,indent=2,default=str)
        #print(self._checkResults)
        #print(dataInJSON)
        
        dataInJSON = json.dumps(self.observables._deMailerObservables["observables"],indent=2,default=str)
        #print(self.observables._deMailerObservables["observables"])
        #print(dataInJSON)
        
        #print("---------------------------------------")
        #dataInJSON = json.dumps(self._deMailerZeus["VirusTotalScans"],indent=2,default=str)
        #print(dataInJSON)

        # Updating deMailerZeus dictionary
        self._deMailerZeus.update(self.observables._deMailerObservables)
        self._deMailerZeus.update(self._checkResults)
        return self._deMailerZeus

    def main(self):

        self.scanmode = args.mode

        if len(sys.argv) == 1:
            print(parser.print_help())
        else:
            if args.vtapi:
                self.vt_api = args.vtapi
            else:
                self.vt_api = None

            if args.vtapi and args.extensive:
                self.vt_extensive = args.extensive
            else:
                # Extensive scan is disabled
                self.vt_extensive = False            
              
            if args.file and args.yara:
                try:
                    yaraDir,yaraFile = self.yarascanner.fileManager(args.yara)
                    if (yaraDir or yaraFile) and args.file:
                        print("\n")
                        print(f"{self.colors.GREEN}[+] Yara scanner ... {self.colors.RESET}")
                        self.yarascanner.yaraScanner(yaraFile,yaraDir,args.file)
                        print("\n")
                except Exception as e:
                    raise(f"[-] Error::{e}")

            deMailerResults = self.deMailerRunner(args.file)
            if deMailer_global_vars.global_variable.EMAIL_ATTACHMENTS_FULL_PATH:
                print(f"{self.colors.GREEN}[+] Email attachments saved under: {deMailer_global_vars.global_variable.EMAIL_ATTACHMENTS_FULL_PATH}{self.colors.RESET}")
            if deMailer_global_vars.global_variable.EMAIL_BODY_TO_TEXT_FULL_PATH:
                print(f"{self.colors.GREEN}[+] Email body converted to text and saved under: {deMailer_global_vars.global_variable.EMAIL_BODY_TO_TEXT_FULL_PATH}{self.colors.RESET}")
            print(f"{self.colors.GREEN}[+] Output saved to HTML file: {deMailer_global_vars.global_variable.OUTPUT_TO_HTML_REPORT}{self.colors.RESET}")
            self.printerpd.finalReport()
            if deMailerResults and args.saveJSON:
                self.saveToFile(args.saveJSON,deMailerResults)

if __name__ == "__main__":

    __banner__.deMailerBanner()
    parser = argparse.ArgumentParser(prog="deMailer",description="[*] Usage: demailer.py -f <*.msg/eml> <argument>",formatter_class=argparse.RawTextHelpFormatter)
    
    group1 = parser.add_argument_group('Required arguments')
    group1.add_argument("-f","--file",action="store",help="Provide an EML/MSG file.",required=True)
    group2 = parser.add_argument_group('VirusTotal')
    group2.add_argument("-vtapi",action="store",help="Scanning observables with VirusTotal [API key is needed].")
    group2.add_argument("-X","--extensive",action="store_true",help="Enable VirusTotal Extensive scan.")
    group3 = parser.add_argument_group('Yara')
    group3.add_argument("-y","--yara",action="store",help="Yara rule(s) directory or file.")
    group4 = parser.add_argument_group('Display modes')
    group4.add_argument("-m","--mode",action="store",type=int,choices=range(0,10),default=0,help='''Print to screen your specified mode (Default:0), 
    [0]=All,[1]=Routing table,[2]=Footprints,[3]=Email addresses,[4]=URLs,[5]=GeoIP,[6]=DNS Lookup,[7]=WhoIs,[8]=Observables,[9]=Checks''')
    group5 = parser.add_argument_group('Output')
    group5.add_argument("-s","--saveJSON",action="store",help="Save results to JSON file.")
    group5.add_argument("--table_format",choices=["plain","simple","github","grid","simple_grid","rounded_grid","heavy_grid","mixed_grid","double_grid","fancy_grid","outline","simple_outline","rounded_outline","heavy_outline","mixed_outline","double_outline","fancy_outline","pipe","orgtbl","asciidoc","jira","presto","pretty","psql","rst","mediawiki","moinmoin","youtrack","html","unsafehtml","latex","latex_raw","latex_booktabs","latex_longtable","textile","tsv"],default="fancy_grid",help="Choose output table format (Default: fancy_grid). More info can be found: https://pypi.org/project/tabulate/")
    group6 = parser.add_argument_group('Exclude from scanning')
    group6.add_argument("--exclude_ips",action="store",default=None,help="Exclude an IP(s) or CIDR from scanning.")
    group6.add_argument("--exclude_domains",action="store",default=None,help="Exclude an Domain(s) from scanning.")
    group6.add_argument("--exclude_emails",action="store",default=None,help="Exclude an Email(s) from scanning.")

    group7 = parser.add_argument_group('Version number')
    group7.add_argument("--version", action="version", version="deMailer V1.0")

    args = parser.parse_args()

    # Set output table format by Tabulate
    deMailer_global_vars.global_variable.TABULATE_TABLE_FORMAT = args.table_format
    # Set the filename of EML/MSG you investigate 
    deMailer_global_vars.global_variable.EMAIL_FILENAME = args.file

    # Exclude for scanning
    if args.exclude_ips:
        WHITELISTED_IPS = args.exclude_ips.split(",")
    if args.exclude_domains:
        WHITELISTED_DOMAINS = args.exclude_domains.split(",")
    if args.exclude_emails:
        WHITELISTED_EMAILS = args.exclude_emails.split(",")

    deMailerCore().main()
