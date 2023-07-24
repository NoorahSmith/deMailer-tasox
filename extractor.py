from lib import *
import re
from email.parser import Parser
from observables import deMailerObservables
from deviator import *
import textwrap
import dns.resolver
from converter import deMailerMsg2EmlConverter,deMailerBodyConverter,deMailerMiscConverter
import deMailer_global_vars
import colors

class deMailerExtractor:
    
    def __init__(self):

        self.urls = []
        self.emailSmtpFrom = []
        self.emailEnvelopFrom = []
        self.emailHeaderFrom = []
        self.allIPv4s = []
        self.allIPv6s = []
        self.emails = []
        self.NaN = "-"
        self.domains = []
        self.messageIDs = []

        
    def extractIPv4(self,received_from):
        """
        Extracts IPv4 values
 
        Arguments
        ---------
        Value: str
            Gets as input the 'Recieved-From' string and extracts IPv6 addresses if present
        
        Return
        ------
        Doesn't return a value
        """
        ipsv4_regex = re.finditer("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",received_from.strip())
        for ipv4 in ipsv4_regex:
            ipv4 = ipv4.group()
            if ipv4 != '' and ipv4 != None:
                try:
                    if ipv4 not in self.allIPv4s:
                        self.allIPv4s.append(ipv4)
                except Exception as e:
                    logging.error(f'{colors.style.YELLOW}[-] Function error extractIPv4() :: {e}{colors.style.RESET}')

    def extractIPv6(self,received_from):
        """
        Extracts IPv6 values
 
        Arguments
        ---------
        Value: str
            Gets as input the 'Recieved-From' string and extracts IPv6 addresses if present
        
        Return
        ------
        Doesn't return a value
        """
        ipsv6_regex = re.finditer("([0-9a-f]{1,4}:+){3,7}[0-9a-f]{1,4}",received_from.strip())
        
        for ipv6 in ipsv6_regex:
            ipv6 = ipv6.group()
            if ipv6 != '' and ipv6 != None:
                try:
                    # IPv6 validation
                    ipaddress.ip_address(ipv6)
                    if ipv6 not in self.allIPv6s:
                        self.allIPv6s.append(ipv6)
                except:
                    continue

    def extractReceivedFromOLD(self,emailHeader) -> str:
        """
        Extracts the contents of 'Received-From:' from the e-mail header

        Arguments
        ----------
        Value: str
            Gets as input the header of an e-mail as a string
        
        Return
        ------
        Received-From: str
            Returns the contents of 'Received: from' header
        """

        received_froms = re.findall("Received: from .*[\n\s\t()\w\d.\-\[\'\],:/=;\<\>@+%]+\w{2,3},\s{1,}\d{1,2}\s\w{3}[\s\n\t].*[\s\n\t]+\d{1,2}:\d{1,2}:\d{1,2}[\w\sa-zA-Z0-9()=_\-\<\>\.@]+", emailHeader)

        return received_froms
    
    def extractReceivedFrom(self,emailHeader) -> str:
        
        """
        Extracts the contents of 'from' from 'Received: from' header

        Arguments
        ----------
        Value: str
            Gets as input the header of an e-mail as a string
        
        Return
        ------
        Received-From: str
            Returns the contents of 'Received: from' header
        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent
        wrapper.replace_whitespace
        
        try:
            if emailHeader:
                # wrapHeader holds header value in list
                wrapHeader = wrapper.wrap(emailHeader)
                # join the list to string
                joinHeader = " ".join(wrapHeader)
                # Extract only the value of 'Received: from'
                receivedFrom = re.search("from [\[\w.:\-\]]+",joinHeader)
                if receivedFrom !=None and receivedFrom:
                    receivedFromStrip = receivedFrom.group().strip()
                    # Strip tabs, nulls etc.
                    receivedFromStrip = " ".join(receivedFromStrip.split())
                    receivedFromReplace = f"{receivedFromStrip.replace('from','').strip()}" 
                else:
                    receivedFromReplace = f"{self.NaN}"
        except ValueError as e:
            raise f"[-] Function extractReceivedFrom() error :: {e}"
        
        return receivedFromReplace

    def extractReceivedBy(self,emailHeader) -> str:
        
        """
        Extracts the contents of 'by' from 'Received: from' header

        Arguments
        ----------
        Value: str
            Gets as input the header of an e-mail as a string
        
        Return
        ------
        Received-From: str
            Returns the contents of 'Received: by' header
        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent
        wrapper.replace_whitespace
        
        try:
            if emailHeader:
                # wrapHeader holds header value in list
                wrapHeader = wrapper.wrap(emailHeader)
                # join the list to string
                joinHeader = " ".join(wrapHeader)
                # Extract only the value of 'Received: from'
                receivedBy = re.search("(?<=by)(.*)(?=with)",joinHeader)
                if receivedBy !=None and receivedBy:
                    receivedByStrip = receivedBy.group().strip()
                    # Strip tabs, nulls etc.
                    receivedByStrip = " ".join(receivedByStrip.split())
                    receivedByReplace = f"{receivedByStrip}" 
                else:
                    receivedByReplace = f"{self.NaN}"
        except ValueError as e:
            raise f"[-] Function extractReceivedBy() error :: {e}"
        
        return receivedByReplace

    def extractReceivedWith(self,emailHeader) -> str:
        
        """
        Extracts the contents of 'With' from 'Received: from' header

        Arguments
        ----------
        Value: str
            Gets as input the header of an e-mail as a string
        
        Return
        ------
        Received-From: str
            Returns the contents of 'Received: With' header
        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent
        wrapper.replace_whitespace
        
        try:
            if emailHeader:
                # wrapHeader holds header value in list
                wrapHeader = wrapper.wrap(emailHeader)
                # join the list to string
                joinHeader = " ".join(wrapHeader)
                # Extract 'Received: from' the value between 'by'<>'for or ;'
                receivedByForRange = re.search("(?<=by)(.*)(?=(for|;))",joinHeader)
                # if 'receivedByForRange' in not None
                if receivedByForRange !=None and receivedByForRange:
                    # Extract the value between 'by'<>'for' inside 'Received: from'
                    receivedByForRangeString = receivedByForRange.group().strip()
                    # From extracted 'by'<>'from' extract 'with'<>'for'. In this range 'With' is located
                    receivedWith = re.search("(?<=with)(.*)(?=for)",receivedByForRangeString)
                    if receivedWith != None:
                        receivedWithStrip = receivedWith.group().strip()
                        # Strip tabs, nulls etc.
                        receivedWithStrip = " ".join(receivedWithStrip.split())
                        receivedWithReplace = f"{receivedWithStrip}"
                    else:
                        receivedWithReplace = f"{self.NaN}"     
                else:
                    receivedWithReplace = f"{self.NaN}"
        
        except ValueError as e:
            raise f"[-] Function extractReceivedWith() error :: {e}"
        
        return receivedWithReplace
            
    def extractDate(self,emailHeader) -> str:
        """
        Extracts the Date from 'Received: from' header

        Arguments
        ----------
        Value: str
            Gets as input the header of an e-mail as a string
        
        Return
        ------
        Date: str
            Returns the Date value of 'Received: from' header
        """
        wrapper = textwrap.TextWrapper()
        wrapper.initial_indent
        wrapper.replace_whitespace
        
        try:
            if emailHeader:
                # wrapHeader holds header value in list
                wrapHeader = wrapper.wrap(emailHeader)
                # join the list to string
                joinHeader = " ".join(wrapHeader)
                # Extract only the value of 'Received: from'
                if joinHeader:
                    receivedFromSplit = joinHeader.split(";")
                
                if len(receivedFromSplit) >1:
                    receivedDateStrip = receivedFromSplit[1].strip()
                    # Strip tabs, nulls etc.
                    receivedDateStrip = " ".join(receivedDateStrip.split())
                    receivedDateReplace = f"{receivedDateStrip}" 
                else:
                    receivedDateReplace = f"{self.NaN}"
        except ValueError as e:
            raise f"[-] Function extractReceivedFrom() error :: {e}"
        
        return receivedDateReplace

    def extractEmail(self,text: str) ->list:
        """
        Extracts an e-mail address from a text 

        Arguments
        ---------
            Value: str

        Return
        ------
        Doesn't return any value
        """
        emailAddrs = []
        email_address = ""
        # From 'By' line, extract 'Email' address
        try:
            # Use 'finditer' because more than one emails can be in one line.
            emails = re.finditer("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",text.strip())
            if emails != None and emails:
                for email in emails:
                    if email != None and email != '':
                        email = email.group()
                        email_address = email.lower().strip()
                        if email_address not in self.emails:
                            self.emails.append(email_address)
                        if email_address not in emailAddrs:
                            emailAddrs.append(email_address)
        except Exception as e:
            logging.error(f'::Function Error->extractEmail::{e}')
        
        return emailAddrs

    def extractEmailEnvelopeFrom(self,received_by: str) ->str:

        """
        Extracts an e-mail address from a 'Envelop-From' header

        Arguments
        ---------
        Value: str
            Gets as input the 'Received: By' string and extracts the e-mail address from 'Envelop-From' if present
        
        Return:
        ------- 
        Envelop-From: str
        """

        try:
            envelope_from_line = re.search("([e|E]nvelope-[f|F]rom).*[<a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",received_by.replace('\n', ''))
            if envelope_from_line != None and envelope_from_line:
                envelope_from_line = envelope_from_line.group()
                envelope_from = re.search("\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\\b",envelope_from_line)
                envelope_from = envelope_from.group().lower().strip()
                #Add 'envelope_from' to list. Later on, I'll compare it with 'From:' value.
                if envelope_from not in self.emailEnvelopFrom:
                    self.emailEnvelopFrom.append(envelope_from)
                if envelope_from not in self.emails:
                    self.emails.append(envelope_from)
            else:
                envelope_from = f"{self.NaN}"

        except Exception as e:
            logging.error(f'::Function Error->extractEmailEnvelopeFrom::{e}')

        return envelope_from.strip()

    def extractEmailSmtpFrom(self,data: str) -> str:

        """
        Extracts an e-mail address from 'smtp.mailfrom' attribute

        Arguments
        ---------
        Value: str
            Gets as input a string and extracts the e-mail address from 'smtp.mailfrom' if present
        
        Return:
        ------- 
        Smtp-from: str
        """

        try:
            smtp_from_line = re.search("(?<=smtp.mailfrom=).*[<a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",data.replace('\n', ''))
            if smtp_from_line != None and smtp_from_line:
                smtp_from_line = smtp_from_line.group()
                smtp_from = re.search("\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\\b",smtp_from_line)
                smtp_from = smtp_from.group().lower().strip()
                #Add 'smtp_from' to list. Later on, I'll compare it with 'From:' value.
                if smtp_from not in self.emailSmtpFrom:
                    self.emailSmtpFrom.append(smtp_from)
                if smtp_from not in self.emails:
                    self.emails.append(smtp_from)
            else:
                smtp_from = f"{self.NaN}"

        except Exception as e:
            logging.error(f'::Function Error->extractEmailSmtpFrom::{e}')

        return smtp_from.strip()
    
    def extractEmailHeaderFrom(self,data:str) -> str:

        """
        Extracts an e-mail address from 'header.from' attribute

        Arguments
        ---------
        Value: str
            Gets as input a string and extracts the e-mail address from 'header.from' if present
        
        Return:
        ------- 
        header.from: str
        """
        try:
            #header_from_line = re.search("(?<=header.from=).*(?=;)",data.replace('\n', ''))
            header_from_line = re.search("(?<=header.from=)[\w\d._-]+",data.replace('\n', ''))

            if header_from_line != None and header_from_line:
                header_from = header_from_line.group()
                header_from = header_from.lower().strip()
                #Add 'smtp_from' to list. Later on, I'll compare it with 'From:' value.
                if header_from not in self.emailHeaderFrom:
                    self.emailHeaderFrom.append(header_from)
                if header_from not in self.domains:
                    self.domains.append(header_from)
            else:
                header_from = f"{self.NaN}"

        except Exception as e:
            logging.error(f'::Function Error->extractEmailHeaderFrom::{e}')
        
        return header_from.strip()

    def extractURLs(self,text: str):

        """
        Extracts a URL address from a text

        Arguments
        ---------
        Value: str
        
        Return:
        ------- 
        Doesn't return any value
        """
        try:
            # Use 'finditer' because more than one urls can be in one line.
            urls = re.finditer(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,=<>?«»“”‘’]))",text.replace("=\n",""))
            if urls != None and urls:
                for url in urls:
                    if url != None and url != '':
                        url = url.group()
                        if url not in self.urls:
                            self.urls.append(url.lower().strip())
        except Exception as e:
            logging.error(f'::Function Error->extractURLs::{e}')
    
    def extractBody(self,emlFile: str):

        """
        This function gets as input an EML file, extracts the attachments and save them under the folder `/attachments`.
        If the e-mail doesn't include attachments and the body is text or has a 'Content-Type: text/plain', it pass those values to 'body2txt' function to convert the body into text.   
        Otherwise, the flow will redirect the flow to 'body2img' function to convert the body into image.

        Arguments
        ---------
        Value: file
            EML file path as input

        Return
        ------
        Doesn't return any value
        """
        #https://stackoverflow.com/questions/3449220/how-do-i-recieve-a-html-email-as-a-regular-text
        openEml = open(emlFile,"r")
        readEml = openEml.read()
        emlToString = email.message_from_string(readEml)
        payloads = email.message.Message.get_payload(emlToString)
        body = ""
        attachments = []
        if len(payloads)>0 and type(payloads) != str:
            for p in payloads:
                for payload in p.walk():
                    try:
                        if payload.get_content_type() in ["text/html","multipart/related"] and payload.get_content_disposition() != "attachment":
                            if payload.get("Content-Transfer-Encoding") == "base64":
                                payLoad = payload.get_payload(decode=True)
                                body+=payLoad.decode('utf-8')
                            elif payload.get("Content-Transfer-Encoding") != "base64":
                                payLoad = payload.get_payload(decode=False)
                                body+=payLoad
                        elif payload.get_content_disposition() == "attachment":
                            if payload.get("Content-Transfer-Encoding") == "base64":
                                cwd = os.getcwd()
                                fileName = payload.get_filename()
                                os.makedirs(cwd + '/' + 'attachments', exist_ok=True)
                                fileFullPath = Path(cwd + "/attachments/" + fileName)
                                with open(fileFullPath, "wb") as binary_file:
                                    binary_file.write(payload.get_payload(decode=True))
                                
                                if fileFullPath:    
                                    attachments.append(str(fileFullPath))
                                #deMailer_global_vars.global_variable.EMAIL_ATTACHMENTS_FULL_PATH = fileFullPath
                                #print(colored(f"[+] Attachments saved under: {fileFullPath}","yellow",attrs=["bold"]))
                        elif payload.get_content_type() in ["text/plain"] and payload.get_content_disposition() != "attachment":
                            if payload.get("Content-Transfer-Encoding") == "base64":
                                    payLoad = payload.get_payload(decode=True)
                                    body+=payLoad.decode('utf-8')
                            elif payload.get("Content-Transfer-Encoding") != "base64":
                                payLoad = payload.get_payload(decode=False)
                                body+=payLoad    
                    except Exception as e:
                        logging.error(f'{colors.style.YELLOW}[-] Function Error->extractBody::{e}{colors.style.RESET}')

            if body !="":
                deMailerBodyConverter().body2txt(body)

        elif len(payloads)>0 and type(payloads) == str:
            body = payloads
            deMailerBodyConverter().body2txt(body)
        
        deMailer_global_vars.global_variable.EMAIL_ATTACHMENTS_FULL_PATH = attachments
    
    def extractHeadersV2(self,emlFile: str) -> dict:

        """
        Extracts e-mail headers and their values.
        
        Parameters
        ----------
        Value: str
            Full *.EML file path

        Return
        ------
        Values : dict
            E-mail headers with their values 
        """
        try:
            openEml = open(emlFile,"r")
            headers = Parser().parse(openEml)

        except Exception as e:
            raise Exception(f"[-] Function extractHeadersV2 through an error while reading the EML file::{e}")
        
        return headers
    
    def extractPayload(self,emlFile: str) -> list:
        
        payloads = None
        try:
            openEml = open(emlFile,"r")
            readEml = openEml.read()
            emlToString = email.message_from_string(readEml)
            payloads = email.message.Message.get_payload(emlToString)
        
        except Exception as e:
            raise Exception(f"[-] extractPayload function error::{e}")

        return payloads

    def extractDomain(self,emailHeader:str) -> list:

        """
        Extracts Domain Names from a text 

        Arguments
        ---------
            Value: str

        Return
        ------
        Doesn't return any value
        """
        domainNames = []
        domainName = ""

        try:
            if "@" in emailHeader:
                # Use 'finditer' because more than one emails can be in one line.
                emails = re.finditer("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",emailHeader.strip())

                if emails != None and emails:
                    for email in emails:
                        if email != None and email != '':
                            email = email.group()
                            email_address = email.lower().strip()
                            # extract Domain Name from Email address
                            domainName = email_address.split("@")[1]
                            if domainName not in self.domains:
                                self.domains.append(domainName)
                            if domainName not in domainNames:
                                domainNames.append(domainName)

        except Exception as e:
            logging.error(f'{colors.style.YELLOW}[-] Function Error->extractDomains::{e}{colors.style.RESET}')
        
        return domainNames

    def extractMessageID(self,emailHeader:str) ->str:
        """
        Extracts an the Message-ID

        Arguments
        ---------
        Value: str
            Gets as input a string and extracts the Message-ID
        
        Return:
        ------- 
        messageIdDomain: str
            Returns the domain of Message-ID email. for example: google.com
        """
        try:
            # Extract the domain from 'Message-ID'
            messageIdDomain = re.search("@[\w.-]+","".join(emailHeader))
            if messageIdDomain != None and messageIdDomain:
                messageIdDomain = messageIdDomain.group().replace("@","")
                messageIdDomain = messageIdDomain.lower().strip()
                if messageIdDomain not in self.messageIDs:
                    self.messageIDs.append(messageIdDomain)
                if messageIdDomain not in self.domains:
                    self.domains.append(messageIdDomain)
            else:
                messageIdDomain = self.NaN

        except Exception as e:
            logging.error(f'{colors.style.YELLOW}[-] Function Error->extractMessageID::{e}{colors.style.RESET}')
        
            return messageIdDomain.strip()

    def extractSPFValidation(self,emailHeader: str) -> str:

        """
        Extracts an the SPF validation value from the 'Authentication-Results' header

        Arguments
        ---------
        emailHeader: str
            Gets as input a string and extracts the SPF validation
        
        Return:
        ------- 
        spfValue: str
            Returns the validation value of SPF. for example: pass or fail
        """
        try:
            # Extract the SPF validation
            receivedSPF_validation = re.search("spf=(pass|fail|soft fail|neutral)",emailHeader.strip())
            if receivedSPF_validation != None and receivedSPF_validation:
                receivedSPFvalue = receivedSPF_validation.group().lower().split("=")[1]
            else:
                receivedSPFvalue = self.NaN

        except Exception as e:
            logging.error(f'{colors.style.YELLOW}[-] Function Error->extractSPF::{e}{colors.style.RESET}')
        
        return receivedSPFvalue
    
    def extractDKIMValidation(self,emailHeader: str) -> str:

        """
        Extracts an the DKIM validation value from the header

        Arguments
        ---------
        emailHeader: str
            Gets as input a string and extracts the DKIM validation
        
        Return:
        ------- 
        dkimValue: str
            Returns the validation value of DKIM. for example: pass or fail
        """
        try:
            # Extract the DKIM validation
            receivedDKIM_validation = re.search("dkim=(pass|fail|soft fail|neutral)",emailHeader.replace('\n', ''))
            if receivedDKIM_validation != None and receivedDKIM_validation:
                receivedDKIMvalue = receivedDKIM_validation.group().lower().split("=")[1]
            else:
                receivedDKIMvalue = self.NaN

        except Exception as e:
            logging.error(f'{colors.style.YELLOW}[-] Function Error->extractDKIM::{e}{colors.style.RESET}')
        
        return receivedDKIMvalue.strip()
    
    def extractDKIMdomain(self,emailHeader: str) -> str:

        """
        Extracts an the DKIM Domain value from the header

        Arguments
        ---------
        emailHeader: str
            Gets as input a string and extracts the domain from DKIM header. for example: d=gmail.com
        
        Return:
        ------- 
        dkimValue: str
            Returns the validation value of DKIM. for example: pass or fail
        """
        try:
            # Extract's domain from DKIM
            receivedDKIM_domain = re.search("d=[\w.-]+",emailHeader.replace('\n', ''))
            if receivedDKIM_domain != None and receivedDKIM_domain:
                receivedDKIMdomainValue = receivedDKIM_domain.group().lower().split("=")[1]
                if receivedDKIMdomainValue not in self.domains:
                    self.domains.append(receivedDKIMdomainValue)
            else:
                receivedDKIMdomainValue = self.NaN

        except Exception as e:
            logging.error(f'{colors.style.YELLOW}[-] Function Error->extractDKIMdomain::{e}{colors.style.RESET}')
        
        return receivedDKIMdomainValue.strip()

    def extractDKIMselector(self,emailHeader: str) -> str:

        """
        Extracts an the DKIM Selector value from the header

        Arguments
        ---------
        emailHeader: str
            Gets as input a string and extracts the domain from DKIM header. for example: s=selector
        
        Return:
        ------- 
        dkimValue: str
            Returns the validation value of DKIM. for example: pass or fail
        """
        try:
            # Extract's domain from DKIM
            receivedDKIM_selector = re.search("s=[\w.-]+",emailHeader.replace('\n', ''))
            if receivedDKIM_selector != None and receivedDKIM_selector:
                receivedDKIMselectorValue = receivedDKIM_selector.group().lower().split("=")[1]
                #if receivedDKIMdomainValue not in self.domains:
                #    self.domains.append(receivedDKIMdomainValue)
            else:
                receivedDKIMselectorValue = self.NaN

        except Exception as e:
            logging.error(f'{colors.style.YELLOW}[-] Function Error->extractDKIMselector::{e}{colors.style.RESET}')
        
        return receivedDKIMselectorValue.strip()
    
    def extractDKIMAuthenticationResultsheaderDomain(self,emailHeader: str) -> str:

        """
        Extracts from DKIM-Signature header the -> header.d

        Arguments
        ---------
        emailHeader: str
            Gets as input a string and extracts the domain from DKIM header. for example: DKIM-Signature: header.d=gmail.com
        
        Return:
        ------- 
        dkimValue: str
            Returns the validation value of DKIM. for example: pass or fail
        """
        try:
            # Extract's domain from DKIM
            DKIM_headerDomain = re.search("header.i=@[\w.-]+",emailHeader.replace('\n', ''))
            if DKIM_headerDomain != None and DKIM_headerDomain:
                DKIM_headerDomainValue = DKIM_headerDomain.group().lower().split("=")[1]
                DKIM_headerDomainValue = DKIM_headerDomainValue.replace('@','')
                if DKIM_headerDomainValue not in self.domains:
                    self.domains.append(DKIM_headerDomainValue)
            else:
                DKIM_headerDomainValue = self.NaN

        except Exception as e:
            logging.error(f'{colors.style.YELLOW}[-] Function Error->extractDKIMAuthenticationResultsheaderDomain::{e}{colors.style.RESET}')
        
        return DKIM_headerDomainValue.strip()
    
    def extractDKIMAuthenticationResultsheaderSelector(self,emailHeader: str) -> str:

        """
        Extracts from DKIM-Signature header the -> header.s

        Arguments
        ---------
        emailHeader: str
            Gets as input a string and extracts the domain from DKIM header. for example: DKIM-Signature: header.s=selector1
        
        Return:
        ------- 
        dkimValue: str
            Returns the validation value of DKIM. for example: pass or fail
        """
        try:
            # Extract's domain from DKIM
            DKIM_headerSelector = re.search("header.s=[\w.-]+",emailHeader.replace('\n', ''))
            if DKIM_headerSelector != None and DKIM_headerSelector:
                DKIM_headerSelectorValue = DKIM_headerSelector.group().lower().split("=")[1]
                #if DKIM_headerSelectorValue not in self.domains:
                #    self.domains.append(DKIM_headerDomainValue)
            else:
                DKIM_headerSelectorValue = self.NaN

        except Exception as e:
            logging.error(f'{colors.style.YELLOW}[-] Function Error->extractDKIMAuthenticationResultsheaderSelector::{e}{colors.style.RESET}')
        
        return DKIM_headerSelectorValue.strip()

    def extractReceivedSPF(self,emailHeader: str) -> str:

        """
        Extracts an the SPF validation value from the 'Received-SPF' header

        Arguments
        ---------
        emailHeader: str
            Gets as input a string and extracts the SPF validation
        
        Return:
        ------- 
        spfValue: str
            Returns the validation value of SPF. for example: pass or fail
        """
        try:
            # Extract the SPF validation
            receivedSPF_validation = re.search(r"^(P|p)(a|A)(s|S)(s|S)\b",emailHeader.strip())
            if receivedSPF_validation != None and receivedSPF_validation:
                receivedSPFvalue = receivedSPF_validation.group().lower()
            else:
                receivedSPFvalue = self.NaN

        except Exception as e:
            logging.error(f'{colors.style.YELLOW}[-] Function Error->extractSPF::{e}{colors.style.RESET}')
        
            return receivedSPFvalue

class deMailerExtractorUpdater:

    def __init__(self):

        self.observables = deMailerObservables()
        self.deviator = deMailerDeviator()

    
    #def updateEmails(self):

        # Extract all emails
    #    emailAddr = deMailerExtractor().extractEmail(headerValue)
            
    def updateEmailSmtpFrom(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `smtp.from` attribute and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """

        # Extract e-mail from smtp.from
        #smtpFrom = self.extract.extractEmailSmtpFrom(headerValue)
        smtpFrom = headerValue

        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
        if keyExists:
            # Check if 'smtpFrom' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","smtpFrom")
            if not keyExists:
                deMailerZeus["emails"].update({"smtpFrom":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"smtpFrom":[]})

        # Update 'smtpFrom'
        if smtpFrom not in self.deviator._deMailerDeviator["emailWhitelisting"] and smtpFrom not in deMailerZeus["emails"]["smtpFrom"]:
            deMailerZeus["emails"]["smtpFrom"].append(smtpFrom)

    def updateEmailEnvelopFrom(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `Envelop-From` attribute and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """

        # Extract e-mail from 'Envelop-From'
        #envelopFrom = self.extract.extractEmailEnvelopeFrom(headerValue)
        envelopFrom = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
    
        if keyExists:
            # Check if 'smtpFrom' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","envelopFrom")
            if not keyExists:
                deMailerZeus["emails"].update({"envelopFrom":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"envelopFrom":[]})
                
        # Update 'envelopFrom'
        if envelopFrom not in self.deviator._deMailerDeviator["emailWhitelisting"] and envelopFrom not in deMailerZeus["emails"]["envelopFrom"]:
            deMailerZeus["emails"]["envelopFrom"].append(envelopFrom)
    
    def updateEmailHeaderFrom(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `header.from` attribute and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """

        # Extract e-mail from 'header.from'
        #envelopFrom = self.extract.extractEmailEnvelopeFrom(headerValue)
        headerFrom = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
    
        if keyExists:
            # Check if 'smtpFrom' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","headerFrom")
            if not keyExists:
                deMailerZeus["emails"].update({"headerFrom":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"headerFrom":[]})
                
        # Update 'headerFrom'
        if headerFrom not in self.deviator._deMailerDeviator["domainNameWhitelisting"] and headerFrom not in deMailerZeus["emails"]["headerFrom"]:
            deMailerZeus["emails"]["headerFrom"].append(headerFrom)
            
    def updateEmailFrom(self,headerValue,deMailerZeus: dict):        
            
        """
        Extracts the any e-mail address from the `From` header and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """

        # Extract e-mail from 'From'
        #mailFrom = deMailerExtractor().extractEmail(headerValue)
        emailsFrom = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
    
        if keyExists:
            # Check if 'from' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","from")
            if not keyExists:
                deMailerZeus["emails"].update({"from":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"from":[]})

        # Update 'from'
        if len(emailsFrom) > 0:
            for emailFrom in emailsFrom:
                if emailFrom not in self.deviator._deMailerDeviator["emailWhitelisting"] and emailFrom not in deMailerZeus["emails"]["from"]:
                    deMailerZeus["emails"]["from"].append(emailFrom)    
            
    def updateEmailTo(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `To` header and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """
    
        # Extract e-mail from 'To'
        #emailTo = deMailerExtractor().extractEmail(headerValue)
        emailTos = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
    
        if keyExists:
            # Check if 'to' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","to")
            if not keyExists:
                deMailerZeus["emails"].update({"to":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"to":[]})

        # Update 'to'
        if len(emailTos) > 0:
            for emailTo in emailTos:
                if emailTo not in self.deviator._deMailerDeviator["emailWhitelisting"] and emailTo not in deMailerZeus["emails"]["to"]:
                    deMailerZeus["emails"]["to"].append(emailTo)

    def updateEmailReplyTo(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `Reply-To` header and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """
    
        # Extract e-mail from 'Reply-To'
        #emailTo = deMailerExtractor().extractEmail(headerValue)
        emailReplyTos = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
    
        if keyExists:
            # Check if 'reply-to' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","reply-to")
            if not keyExists:
                deMailerZeus["emails"].update({"reply-to":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"reply-to":[]})

        # Update 'reply-to'
        if len(emailReplyTos) > 0:
            for emailReplyTo in emailReplyTos:
                if emailReplyTo not in self.deviator._deMailerDeviator["emailWhitelisting"] and emailReplyTo not in deMailerZeus["emails"]["reply-to"]:
                    deMailerZeus["emails"]["reply-to"].append(emailReplyTo)
    
    def updateEmailReturnPath(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `Return-Path` header and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """
    
        # Extract e-mail from 'Return-Path'
        #emailTo = deMailerExtractor().extractEmail(headerValue)
        emailReturnPaths = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
    
        if keyExists:
            # Check if 'return-path' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","return-path")
            if not keyExists:
                deMailerZeus["emails"].update({"return-path":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"return-path":[]})

        # Update 'Return-Path'
        if len(emailReturnPaths) > 0:
            for emailReturnPath in emailReturnPaths:
                if emailReturnPath not in self.deviator._deMailerDeviator["emailWhitelisting"] and emailReturnPath not in deMailerZeus["emails"]["return-path"]:
                    deMailerZeus["emails"]["return-path"].append(emailReturnPath)
    
    def updateEmailMessageID(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `Message-ID` header and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """
    
        # Extract e-mail from 'Return-Path'
        #emailTo = deMailerExtractor().extractEmail(headerValue)
        emailMessageIDs = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
    
        if keyExists:
            # Check if 'message-id' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","message-id")
            if not keyExists:
                deMailerZeus["emails"].update({"message-id":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"message-id":[]})

        # Update 'message-id'
        if len(emailMessageIDs) > 0:
            for emailMessageID in emailMessageIDs:
                if emailMessageID not in self.deviator._deMailerDeviator["emailWhitelisting"] and emailMessageID not in deMailerZeus["emails"]["message-id"]:
                    deMailerZeus["emails"]["message-id"].append(emailMessageID)
    
    def updateEmailDKIMLookUP(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `DKIM-Signature` -> d:<Outbound mail server> header and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """
    
        # emailDKIMDomain_Selector contains: DKIM outbound domain (d) + selector (s) values in dict form -> {"<selector>":"<domain>"}
        emailDKIMDomain_Selector = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"validator")
    
        if keyExists:
            # Check if 'dkim_d' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"validator","dkim")
            if not keyExists:
                deMailerZeus["validator"].update({"dkim":{}})
        else:
            deMailerZeus["validator"] = {}
            deMailerZeus["validator"].update({"dkim":{}})

        # Update 'dkim'
        if emailDKIMDomain_Selector:

            try:
                resolverAnswer = ''
                try:
                    resolverAnswer = dns.resolver.resolve(f"{emailDKIMDomain_Selector}", 'TXT')
                except Exception as e:
                    logging.error(f"Couldn't resolve {emailDKIMDomain_Selector} to retrieve the DKIM-Pubplic key from TXT record. ")
                
                if resolverAnswer:
                    query_name = resolverAnswer.qname
                    # List the holds answers in -> tuple
                    answer_txt_list_tuple = []
                    # List the holds answers in -> string
                    answer_txt_list_str = []

                    if resolverAnswer and resolverAnswer != None and resolverAnswer !='':
                        for x in resolverAnswer:
                            # Adding resolver responses to list -> tuple
                            answer_txt_list_tuple.append(x.strings)

                    encoding = 'utf-8'
                    # Itterate through the answers
                    if len(answer_txt_list_tuple) > 0:
                        for ans in answer_txt_list_tuple:
                            # Every answer is tuple in bytes
                            # Convert the tuple to str
                            # Join the elements in the same tuple
                            res = ''.join([tups.decode(encoding) for tups in ans])
                            if res not in answer_txt_list_str:
                                answer_txt_list_str.append(res)

                    if emailDKIMDomain_Selector not in deMailerZeus["validator"]["dkim"].keys():
                        deMailerZeus["validator"]["dkim"].update({emailDKIMDomain_Selector:{}})
                
                    # Break every answer to extract the elements -> v, k, p
                    if len(answer_txt_list_str) > 0:
                        for ans in answer_txt_list_str:
                            answer_split = ans.split(';')
                            if len(answer_split) >0:
                                for splits in answer_split:
                                    # element -> v=DKIM, k=rsa, p=<SHA256/512>
                                    element = splits.strip()
                                    # Split element -> ['v','DKIM']
                                    elementSplit = element.split("=")
                                    if elementSplit[0] not in deMailerZeus["validator"]["dkim"][emailDKIMDomain_Selector].keys() and len(elementSplit) == 2:
                                        deMailerZeus["validator"]["dkim"][emailDKIMDomain_Selector].update({elementSplit[0]:elementSplit[1]})
            except Exception as e:
                logging.error(f"[-] Funtion updateEmailDKIMLookUP() error :: {e}. Couldn't resolve {emailDKIMDomain_Selector} to get the TXT record.")
  
    def updateEmailCc(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `Cc` header and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """
    
        # Extract e-mail from 'Cc'
        #emailCc = deMailerExtractor().extractEmail(headerValue)
        emailCcs = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
    
        if keyExists:
            # Check if 'cc' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","cc")
            if not keyExists:
                deMailerZeus["emails"].update({"cc":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"cc":[]})

        # Update 'cc'
        if len(emailCcs) > 0:
            for emailCc in emailCcs:
                if emailCc not in self.deviator._deMailerDeviator["emailWhitelisting"] and emailCc not in deMailerZeus["emails"]["cc"]:
                    deMailerZeus["emails"]["cc"].append(emailCc)
    
    def updateEmailBcc(self,headerValue,deMailerZeus: dict):

        """
        Extracts the any e-mail address from the `Bcc` header and updates the dictionary

        Parameters
        ----------
        Doesn't take any parameter 
        """
    
        # Extract e-mail from 'Bcc'
        #emailBcc = deMailerExtractor().extractEmail(headerValue)
        emailBccs = headerValue
        
        # Check if 'emails' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails")
    
        if keyExists:
            # Check if 'cc' key exists in the dictionary
            keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"emails","bcc")
            if not keyExists:
                deMailerZeus["emails"].update({"bcc":[]})
        else:
            deMailerZeus["emails"] = {}
            deMailerZeus["emails"].update({"bcc":[]})

        # Update 'bcc'
        if len(emailBccs) > 0:
            for emailBcc in emailBccs:
                if emailBcc not in self.deviator._deMailerDeviator["emailWhitelisting"] and emailBcc not in deMailerZeus["emails"]["bcc"]:
                    deMailerZeus["emails"]["bcc"].append(emailBcc)

    def updateRoutingTable(self,routingTable:dict,deMailerZeus:dict):
        
        # Check if 'routingTable' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"routingTable")
    
        if len(routingTable) > 0:

            if keyExists:
                deMailerZeus["routingTable"].update(routingTable)
            else:
                deMailerZeus["routingTable"] = {}
                deMailerZeus["routingTable"].update(routingTable)
    
    def updateFootprints(self,emailHeaders:dict,deMailerZeus:dict,checksResults:dict):
        
        counter = 1

        # Check if 'routingTable' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"footprints")
    
        if len(emailHeaders) > 0:
            if not keyExists:
                deMailerZeus["footprints"] = {}
    
        if len(emailHeaders) > 0:
            for key,value in emailHeaders.items():
                # Check if key exists in the header
                keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"footprints",key)
                if not keyExists:
                    deMailerZeus["footprints"].update({key:value})
                else:
                    deMailerZeus["footprints"].update({key+"_"+str(counter):value})
                    counter+=1

    def updateGeoIP(self,emailHeaders:dict,deMailerZeus:dict):

        """
        Updates deMailerZeus with GeoIP data

        Parameters
        ----------
        Doesn't take any parameter 
        """
        # Check if 'geoIPLookUp' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"geoIPLookUp")
    
        if len(emailHeaders) > 0:
            if not keyExists:
                deMailerZeus["geoIPLookUp"] = {}
    
        if len(emailHeaders) > 0:
            for key,value in emailHeaders.items():
                # Check if key exists in the header
                keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"geoIPLookUp",key)
                if not keyExists:
                    deMailerZeus["geoIPLookUp"].update({key:value})
                #else:
                #    deMailerZeus["geoIPLookUp"].update({key+"_"+str(counter):value})
                #    counter+=1

    def updateDnsLookUp(self,emailHeaders:dict,deMailerZeus:dict):

        """
        Updates deMailerZeus with DomainLookUp data

        Parameters
        ----------
        Doesn't take any parameter 
        """
        # Check if 'geoIPLookUp' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"dnsLookUp")
    
        if len(emailHeaders) > 0:
            if not keyExists:
                deMailerZeus["dnsLookUp"] = {}
    
        if len(emailHeaders) > 0:
            for key,value in emailHeaders.items():
                # Check if key exists in the header
                keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"dnsLookUp",key)
                if not keyExists:
                    deMailerZeus["dnsLookUp"].update({key:value})
    
    def updateWhoisLookUp(self,emailHeaders:dict,deMailerZeus:dict):

        """
        Updates deMailerZeus with DomainLookUp data

        Parameters
        ----------
        Doesn't take any parameter 
        """
        # Check if 'geoIPLookUp' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"whoIsLookUp")
    
        if len(emailHeaders) > 0:
            if not keyExists:
                deMailerZeus["whoIsLookUp"] = {}
    
        if len(emailHeaders) > 0:
            for key,value in emailHeaders.items():
                # Check if key exists in the header
                keyExists = self.observables.deMailerZeusKeySearcher(deMailerZeus,"whoIsLookUp",key)
                if not keyExists:
                    deMailerZeus["whoIsLookUp"].update({key:value})
