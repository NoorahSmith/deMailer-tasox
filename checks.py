import re
import extractor
import observables
import dns.resolver
import logging
from email.parser import BytesParser
import dkim
import colors
import dmarc

class deMailerChecks:

    def __init__ (self,enabled: bool =True):

        self.enabled = enabled
        self.extractor = extractor.deMailerExtractor()
        self.observables = observables.deMailerObservables()
        self.NaN = "-"
        self._checkResults = {"headerChecks":{}}
        self.colors = colors.style()
        self.suspicious = f"{self.colors.YELLOW}Suspicious{self.colors.RESET}"
        self.okay = f"{self.colors.GREEN}OK{self.colors.RESET}"
        self.neutral = f"{self.colors.MAGENTA}Neutral{self.colors.RESET}"

        if not enabled:
            raise ValueError('[-] Manual scans are disabled!')
        

    def checkFromWithReturnPath(self,emailFrom:list,returnPath:list):
        """
        This is informational function and doesn't do any comparison.
        Use checkFromWithReturnPathResults instead.
        
        Parameters
        -----------
            emailFrom: A list of emails from 'From' header
            returnPath: A list of emails from 'Return-Path' header
        """
        if not isinstance(emailFrom, list):
            raise AttributeError('checkFromReturnPath() expects list as first argument.')

        if not isinstance(returnPath, list):
            raise AttributeError('checkFromReturnPath() expects list as second argument.')

        # Check if 'checkFromWithReturnPath' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkFromWithReturnPath")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkFromWithReturnPath":[]})
        
        if len(emailFrom) >0 and len(returnPath) >0:
            for emailfrom in emailFrom:
                for returnpath in returnPath:
                    if emailfrom != returnpath:
                        result_message = f"The sender of the e-mail<>{emailfrom} doesn't match with the Return-path<>{returnpath}"
                        results = {"Checking":"From <-> Return-Path","condition1":emailfrom,"condition2":returnpath,"results":result_message,"status":self.suspicious}
                        self._checkResults["headerChecks"]["checkFromWithReturnPath"].append(results) 
                    else:
                        result_message = f"The sender of the e-mail<>[{emailfrom}] matches with the Return-path<>[{returnpath}]"
                        results = {"Checking":"From <-> Return-Path","condition1":emailfrom,"condition2":returnpath,"results":result_message,"status":self.okay}
                        self._checkResults["headerChecks"]["checkFromWithReturnPath"].append(results)

    def checkFromWithReturnPathResults(self,deMailerZeusEmails:dict):

        """
        Checking 'From' and 'Return-Path' properties and uses 'checkFromWithReturnPath' to add the results to checks table.
        
        Parameters
        ----------
            deMailerZeusEmails: Gets as input the email key from deMailerZeus in dict form.
        """
        
        if not isinstance(deMailerZeusEmails, dict):
            raise AttributeError('checkFromWithReturnPathResults() expects dict as first argument.')

        if len(deMailerZeusEmails.items()) > 0:
            for key,value in deMailerZeusEmails.items():
                for key2,value2 in deMailerZeusEmails.items():
                    if key.lower() == 'from' and key2.lower() == 'return-path':
                        try:
                            # self.extractor.extractEmail -> returns list of emails
                            emailFrom = deMailerZeusEmails[key]
                            emailReturnPath = deMailerZeusEmails[key2]
                            if isinstance(emailFrom, list) and isinstance(emailReturnPath,list):
                                if len(emailFrom) > 0 and len(emailReturnPath) > 0:
                                    self.checkFromWithReturnPath(emailFrom,emailReturnPath)
                        except Exception as e:
                            logging.error(e) 

    def checkFromWithMessageID(self,emailFrom:list,messageID:list):

        if not isinstance(emailFrom, list):
            raise AttributeError('checkFromReturnPath() expects list as first argument.')

        if not isinstance(messageID, list):
            raise AttributeError('checkFromMessageID() expects list as second argument.')
        
        # Check if 'checkFromWithMessageID' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkFromWithMessageID")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkFromWithMessageID":[]})
        
        if len(emailFrom) >0 and len(messageID) >0:
            for emailfrom in emailFrom:
                for messageid in messageID:
                    # Return a list
                    emailFromDomains = self.extractor.extractDomain(emailfrom)
                    messageIdDomain = self.extractor.extractDomain(messageid)
                    if len(emailFromDomains) >0 and len(messageIdDomain)>0:
                        for messageiddomain in messageIdDomain:
                            if messageiddomain not in emailFromDomains:
                                result_message = f"The domain name of the Message-ID<>{messageiddomain} is not equal with domain name of the sender<>{emailFromDomains}"
                                results = {"Checking":"Message-ID (Domain) <-> From (Domain)","condition1":messageiddomain,"condition2":emailFromDomains,"results":result_message,"status":self.suspicious}
                                self._checkResults["headerChecks"]["checkFromWithMessageID"].append(results) 
                            elif messageiddomain in emailFromDomains:
                                result_message = f"The domain name of the Message-ID<>{messageiddomain} is equal with domain name of the sender<>{emailFromDomains}"
                                results = {"Checking":"Message-ID (Domain) <-> From (Domain)","condition1":messageiddomain,"condition2":emailFromDomains,"results":result_message,"status":self.okay}
                                self._checkResults["headerChecks"]["checkFromWithMessageID"].append(results)    
        
    def checkFromWithMessageIDResults(self,deMailerZeusEmails:dict):

        if not isinstance(deMailerZeusEmails, dict):
            raise AttributeError('checkFromWithMessageIDResults() expects dict as first argument.')

        if len(deMailerZeusEmails.items()) > 0:
            for key,value in deMailerZeusEmails.items():
                for key2,value2 in deMailerZeusEmails.items():
                    if key.lower() == 'from' and key2.lower() == 'message-id':
                        try:
                            # self.extractor.extractEmail -> returns list of emails
                            emailFrom = deMailerZeusEmails[key]
                            emailMessageID = deMailerZeusEmails[key2]
                            if isinstance(emailFrom, list) and isinstance(emailMessageID,list):
                                if len(emailFrom) > 0 and len(emailMessageID) > 0:
                                    self.checkFromWithMessageID(emailFrom,emailMessageID)
                        except Exception as e:
                            logging.error(e)

    def checkFromWithReplyTo(self,emailFrom:list,replyTo:list):

        if not isinstance(emailFrom, list):
            raise AttributeError('checkFromReplyTo() expects list as first argument.')

        if not isinstance(replyTo, list):
            raise AttributeError('checkFromReplyTo() expects list as second argument.')
        
        # Check if 'checkFromWithReplyTo' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkFromWithReplyTo")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkFromWithReplyTo":[]})
        
        if len(emailFrom) >0 and len(replyTo) >0:
            for emailfrom in emailFrom:
                for replyto in replyTo:
                    if emailfrom != replyto:
                        result_message = f"The sender of the e-mail<>{emailfrom} doesn't match with the Reply-To<>{replyto}"
                        results = {"Checking":"From <-> Reply-To","condition1":emailfrom,"condition2":replyto,"results":result_message,"status":self.suspicious}
                        self._checkResults["headerChecks"]["checkFromWithReplyTo"].append(results)
                    else:
                        result_message = f"The sender of the e-mail<>{emailfrom} matches with the Reply-To<>{replyto}"
                        results = {"Checking":"From <-> Reply-To","condition1":emailfrom,"condition2":replyto,"results":result_message,"status":self.okay}
                        self._checkResults["headerChecks"]["checkFromWithReplyTo"].append(results)
           
    def checkFromWithReplyToResults(self,deMailerZeusEmails:dict):

        if not isinstance(deMailerZeusEmails, dict):
            raise AttributeError('checkFromWithReplyToResults() expects dict as first argument.')

        if len(deMailerZeusEmails.items()) > 0:
            for key,value in deMailerZeusEmails.items():
                for key2,value2 in deMailerZeusEmails.items():
                    if key.lower() == 'from' and key2.lower() == 'reply-to':
                        try:
                            # self.extractor.extractEmail -> returns list of emails
                            emailFrom = deMailerZeusEmails[key]
                            emailReplyTo = deMailerZeusEmails[key2]
                            if isinstance(emailFrom, list) and isinstance(emailReplyTo,list):
                                if len(emailFrom) > 0 and len(emailReplyTo) > 0:
                                    self.checkFromWithReplyTo(emailFrom,emailReplyTo)
                        except Exception as e:
                            logging.error(e)
    
    def checkFromWithEnvelopFrom(self,emailFrom:list,envelopFrom:list):

        if not isinstance(emailFrom, list):
            raise AttributeError('checkFromEnvelopFrom() expects list as first argument.')

        if not isinstance(envelopFrom, list):
            raise AttributeError('checkFromEnvelopFrom() expects list as second argument.')
    
        # Check if 'checkFromWithEnvelopFrom' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkFromWithEnvelopFrom")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkFromWithEnvelopFrom":[]})

        if len(emailFrom) >0 and len(envelopFrom) >0:
            for emailfrom in emailFrom:
                for envelopfrom in envelopFrom:
                    if emailfrom != envelopfrom:
                        result_message = f"The sender of the e-mail<>{emailfrom} doesn't match with the Envelop-From<>{envelopfrom}"
                        results = {"Checking":"From <-> Envelop-From","condition1":emailfrom,"condition2":envelopfrom,"results":result_message,"status":self.suspicious}
                        self._checkResults["headerChecks"]["checkFromWithEnvelopFrom"].append(results)
                    else:
                        result_message = f"The sender of the e-mail<>{emailfrom} matches with the Envelop-From<>{envelopfrom}"
                        results = {"Checking":"From <-> Envelop-From","condition1":emailfrom,"condition2":envelopfrom,"results":result_message,"status":self.okay}
                        self._checkResults["headerChecks"]["checkFromWithEnvelopFrom"].append(results)
    
    def checkFromWithEnvelopFromResults(self,deMailerZeusEmails:dict):

        if not isinstance(deMailerZeusEmails, dict):
            raise AttributeError('checkFromWithEnvelopFromResults() expects dict as first argument.')

        if len(deMailerZeusEmails.items()) > 0:
            for key,value in deMailerZeusEmails.items():
                for key2,value2 in deMailerZeusEmails.items():
                    if key.lower() == 'from' and key2.lower() == 'envelopFrom':
                        try:
                            # self.extractor.extractEmail -> returns list of emails
                            emailFrom = deMailerZeusEmails[key]
                            emailEnvelopFrom = deMailerZeusEmails[key2]
                            if isinstance(emailFrom, list) and isinstance(emailEnvelopFrom,list):
                                if len(emailFrom) > 0 and len(emailEnvelopFrom) > 0:
                                    self.checkFromWithEnvelopFrom(emailFrom,emailEnvelopFrom)
                        except Exception as e:
                            logging.error(e)

    def checkReturnPathWithEnvelopFrom(self,returnPath:list,envelopFrom:list):

        if not isinstance(returnPath, list):
            raise AttributeError('checkReturnPathWithEnvelopFrom() expects list as first argument.')

        if not isinstance(envelopFrom, list):
            raise AttributeError('checkReturnPathWithEnvelopFrom() expects list as second argument.')
    
        # Check if 'checkReturnPathWithEnvelopFrom' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkReturnPathWithEnvelopFrom")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkReturnPathWithEnvelopFrom":[]})

        if len(returnPath) >0 and len(envelopFrom) >0:
            for returnpath in returnPath:
                for envelopfrom in envelopFrom:
                    if returnpath != envelopfrom:
                        result_message = f"The potential reply address of the e-mail<>{returnpath} doesn't match with the Envelop-From<>{envelopfrom}"
                        results = {"Checking":"Return-path <-> Envelop-From","condition1":returnpath,"condition2":envelopfrom,"results":result_message,"status":self.suspicious}
                        self._checkResults["headerChecks"]["checkReturnPathWithEnvelopFrom"].append(results)
                    else:
                        result_message = f"The potential reply address of the e-mail<>{returnpath} matches with the Envelop-From<>{envelopfrom}"
                        results = {"Checking":"Return-path <-> Envelop-From","condition1":returnpath,"condition2":envelopfrom,"results":result_message,"status":self.okay}
                        self._checkResults["headerChecks"]["checkReturnPathWithEnvelopFrom"].append(results)
    
    def checkReturnPathWithEnvelopFromResults(self,deMailerZeusEmails:dict):

        if not isinstance(deMailerZeusEmails, dict):
            raise AttributeError('checkReturnPathWithEnvelopFromResults() expects dict as first argument.')

        if len(deMailerZeusEmails.items()) > 0:
            for key,value in deMailerZeusEmails.items():
                for key2,value2 in deMailerZeusEmails.items():
                    if key.lower() == 'return-path' and key2.lower() == 'envelopFrom':
                        try:
                            # self.extractor.extractEmail -> returns list of emails
                            emailReturnPath = deMailerZeusEmails[key]
                            emailEnvelopFrom = deMailerZeusEmails[key2]
                            if isinstance(emailReturnPath, list) and isinstance(emailEnvelopFrom,list):
                                if len(emailReturnPath) > 0 and len(emailEnvelopFrom) > 0:
                                    self.checkReturnPathWithEnvelopFrom(emailReturnPath,emailEnvelopFrom)
                        except Exception as e:
                            logging.error(e)

    def checkFromWithSmtpFrom(self,emailFrom:list,smtpFrom:list):

        if not isinstance(emailFrom, list):
            raise AttributeError('checkFromSmtpFrom() expects list as first argument.')

        if not isinstance(smtpFrom, list):
            raise AttributeError('checkFromSmtpFrom() expects list as second argument.')
        
        # Check if 'checkFromWithSmtpFrom' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkFromWithSmtpFrom")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkFromWithSmtpFrom":[]})
        
        if len(emailFrom) >0 and len(smtpFrom) >0:
            for emailfrom in emailFrom:
                for smtpfrom in smtpFrom:
                    if emailfrom != smtpfrom:
                        result_message = f"The sender of the e-mail<>{emailfrom} doesn't match with the smtp.mailfrom<>{smtpfrom}"
                        results = {"Checking":"From <-> email.smtpfrom","condition1":emailfrom,"condition2":smtpfrom,"results":result_message,"status":self.suspicious}
                        self._checkResults["headerChecks"]["checkFromWithSmtpFrom"].append(results)
                    else:
                        result_message = f"The sender of the e-mail<>{emailfrom} matches with the smtp.mailfrom<>{smtpfrom}"
                        results = {"Checking":"From <-> email.smtpfrom","condition1":emailfrom,"condition2":smtpfrom,"results":result_message,"status":self.okay}
                        self._checkResults["headerChecks"]["checkFromWithSmtpFrom"].append(results)

    def checkFromWithSmtpFromResults(self,deMailerZeusEmails:dict):

        if not isinstance(deMailerZeusEmails, dict):
            raise AttributeError('checkFromWithSmtpFromResults() expects dict as first argument.')

        if len(deMailerZeusEmails.items()) > 0:
            for key,value in deMailerZeusEmails.items():
                for key2,value2 in deMailerZeusEmails.items():
                    if key.lower() == 'from' and key2.lower() == 'smtpfrom':
                        try:
                            # self.extractor.extractEmail -> returns list of emails
                            emailFrom = deMailerZeusEmails[key]
                            emailSmtpFrom = deMailerZeusEmails[key2]
                            if isinstance(emailFrom, list) and isinstance(emailSmtpFrom,list):
                                if len(emailFrom) > 0 and len(emailSmtpFrom) > 0:
                                    self.checkFromWithSmtpFrom(emailFrom,emailSmtpFrom)
                        except Exception as e:
                            logging.error(e)

    def checkFromWithDKIMdomain(self,emailFrom:list,dkimDomains:list):

        """
        It looks if the doamins of the emails sender 'From' matches with the domain that DKIM header holds.  
        """

        if not isinstance(emailFrom, list):
            raise AttributeError('checkFromDKIMdomain() expects list as first argument.')

        if not isinstance(dkimDomains, list):
            raise AttributeError('checkFromDKIMdomain() expects list as second argument.')
        
        # Check if 'checkFromWithDKIMdomain' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkFromWithDKIMdomain")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkFromWithDKIMdomain":[]})
        
        if len(emailFrom) >0 and len(dkimDomains) >0:
            for emailfrom in emailFrom:
                # Extract Domain -> List
                emailFromDomainList = self.extractor.extractDomain(emailfrom)
                emailFromDomainStr = ''.join(emailFromDomainList)
                emailFromDomainLower = emailFromDomainStr.lower()
                for dkimdomain in dkimDomains:
                    if emailFromDomainLower != dkimdomain:
                        result_message = f"The domain of the sender From: <>[{emailFromDomainLower}] doesn't match with DKIM's domain<>[{dkimdomain}]"
                        results = {"Checking":"From <-> DKIM Domain","condition1":emailFromDomainLower,"condition2":dkimdomain,"results":result_message,"status":self.suspicious}
                        self._checkResults["headerChecks"]["checkFromWithDKIMdomain"].append(results)
                    else:
                        result_message = f"The domain of the sender From: <>[{emailFromDomainLower}] matches with DKIM's domain<>[{dkimdomain}]"
                        results = {"Checking":"From <-> DKIM Domain","condition1":emailFromDomainLower,"condition2":dkimdomain,"results":result_message,"status":self.okay}
                        self._checkResults["headerChecks"]["checkFromWithDKIMdomain"].append(results)
    
    def checkEnvelopFromWithDKIMdomain(self,envelopFrom:list,dkimDomains:list):

        """
        It looks if the doamins of the email header 'Envelop-From' matches with the domain that DKIM header holds.  
        """

        if not isinstance(envelopFrom, list):
            raise AttributeError('checkEnvelopFromWithDKIMdomain() expects list as first argument.')

        if not isinstance(dkimDomains, list):
            raise AttributeError('checkEnvelopFromWithDKIMdomain() expects list as second argument.')
        
        # Check if 'checkEnvelopFromWithDKIMdomain' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkEnvelopFromWithDKIMdomain")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkEnvelopFromWithDKIMdomain":[]})
        
        if len(envelopFrom) >0 and len(dkimDomains) >0:
            for envelopfrom in envelopFrom:
                # Extract Domain -> List
                emailEnvelopFromDomainList = self.extractor.extractDomain(envelopfrom)
                emailEnvelopFromDomainStr = ''.join(emailEnvelopFromDomainList)
                emailEnvelopFromDomainLower = emailEnvelopFromDomainStr.lower()
                for dkimdomain in dkimDomains:
                    if emailEnvelopFromDomainLower != dkimdomain:
                        result_message = f"The domain of the sender Envelop-From: <>[{emailEnvelopFromDomainLower}] doesn't match with DKIM's domain<>[{dkimdomain}]"
                        results = {"Checking":"EnvelopFrom <-> DKIM Domain","condition1":emailEnvelopFromDomainLower,"condition2":dkimdomain,"results":result_message,"status":self.suspicious}
                        self._checkResults["headerChecks"]["checkEnvelopFromWithDKIMdomain"].append(results)
                    else:
                        result_message = f"The domain of the sender Envelop-From: <>[{emailEnvelopFromDomainLower}] matches with DKIM's domain<>[{dkimdomain}]"
                        results = {"Checking":"EnvelopFrom <-> DKIM Domain","condition1":emailEnvelopFromDomainLower,"condition2":dkimdomain,"results":result_message,"status":self.okay}
                        self._checkResults["headerChecks"]["checkEnvelopFromWithDKIMdomain"].append(results)
     
    def checkSPFvalidation(self,spfResults:str,spfHeaderValue):

        if not isinstance(spfResults,str):
            raise AttributeError('checkSPFvalidation() expects a string as first argument.')
        
        # Check if 'checkSPFvalidation' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkSPFvalidation")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkSPFvalidation":[]})
        
        if spfResults:
            if spfResults == "pass":
                result_message = f"SPF validation has value -> [{spfResults}]"
                results = {"Checking":"Checking the results of the SPF validation","condition1":f"Authentication-Results: {spfHeaderValue}","condition2":self.NaN,"results":result_message,"status":self.okay}
                self._checkResults["headerChecks"]["checkSPFvalidation"].append(results)
            elif spfResults in ["fail","soft fail","neutral"]:
                result_message = f"SPF validation has value -> [{spfResults}]"
                results = {"Checking":"Checking the results of the SPF validation","condition1":f"Authentication-Results: {spfHeaderValue}","condition2":self.NaN,"results":result_message,"status":self.suspicious}
                self._checkResults["headerChecks"]["checkSPFvalidation"].append(results)
            elif spfResults == self.NaN:
                result_message = f"SPF validation has value -> [{spfResults}]"
                results = {"Checking":"Checking the results of the SPF validation","condition1":f"Authentication-Results: {spfHeaderValue}","condition2":self.NaN,"results":result_message,"status":self.neutral}
                self._checkResults["headerChecks"]["checkSPFvalidation"].append(results)

    def checkDKIMLookUP(self,dkimDomain:str,dkimSelector:str):

        if not isinstance(dkimDomain, str):
            raise AttributeError('checkDKIMLookUP() expects a string as first argument.')
        
        if not isinstance(dkimSelector, str):
            raise AttributeError('checkDKIMLookUP() expects a string as second argument.')
        
        # Check if 'checkDKIMLookUP' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkDKIMLookUP")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkDKIMLookUP":[]})
        
        if dkimDomain and dkimSelector:
            try:
                resolverAnswer=''
                try:
                    resolverAnswer = dns.resolver.resolve(f"{dkimSelector}._domainkey.{dkimDomain}", 'TXT')
                except Exception as e:
                    logging.error(f"Couldn't resolve {dkimSelector}._domainkey.{dkimDomain} to retrieve the DKIM-Public key from TXT record. ")

                if resolverAnswer:   
                    query_name = resolverAnswer.qname
                    # List the holds answers in -> tuple
                    answer_txt_list_tuple = []
                    # List the holds answers in -> string
                    answer_txt_list_str = []

                    for x in resolverAnswer:
                        # Adding resolver responses to list -> tuple
                        answer_txt_list_tuple.append(x.strings)
                    
                    encoding = 'utf-8'
                    # Itterate through the answers
                    for ans in answer_txt_list_tuple:
                        # Every answer is tuple in bytes
                        # Convert the tuple to str
                        # Join the elements in the same tuple
                        res = ''.join([tups.decode(encoding) for tups in ans])
                        if res not in answer_txt_list_str:
                            answer_txt_list_str.append(res)
                    
                    if len(answer_txt_list_tuple) > 0:
                        for answer in resolverAnswer:
                            if answer and answer !="":
                                result_message = f"DKIM-Public key is present"
                                dkim_signature = answer_txt_list_str
                                results = {"Checking":"DKIM-Signature d (Domain)<-> s(selector)","condition1":dkimDomain,"condition2":dkimSelector,"results":result_message,"dkim-signature":dkim_signature,"status":self.okay}
                                self._checkResults["headerChecks"]["checkDKIMLookUP"].append(results)
                else:
                    result_message = f"DKIM-Public key is not present"
                    dkim_signature = self.NaN
                    results = {"Checking":"DKIM-Signature d (Domain)<-> s(selector)","condition1":dkimDomain,"condition2":dkimSelector,"results":result_message,"dkim-signature":dkim_signature,"status":self.suspicious}
                    self._checkResults["headerChecks"]["checkDKIMLookUP"].append(results)
                            
            except Exception as e:
                logging.error(f"[-] Function error checkDKIMLookUP() :: {e}")
    
    def checkDKIMAuthenticationResults(self,dkimDomain:str,dkimSelector:str,dkimAuthResults:str):

        if not isinstance(dkimDomain, str):
            raise AttributeError('checkDKIMAuthenticationResults() expects a string as first argument.')
        
        if not isinstance(dkimSelector, str):
            raise AttributeError('checkDKIMAuthenticationResults() expects a string as second argument.')
        
        if not isinstance(dkimAuthResults, str):
            raise AttributeError('checkDKIMAuthenticationResults() expects a string as third argument.')
        
        # Check if 'checkDKIMAuthenticationResults' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkDKIMAuthenticationResults")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkDKIMAuthenticationResults":[]})
        
        if dkimDomain and dkimSelector and dkimAuthResults:

            if dkimAuthResults.lower() == 'pass':     
                result_message = f"Authentication-Results showed that DKIM passed provider's verification check -> {dkimAuthResults}"
                results = {"Checking":f"DKIM results in Authenication-Results -> header.s={dkimSelector} <-> header.i={dkimDomain}","condition1":dkimDomain+" (Domain)","condition2":dkimSelector+" (Selector)","results":result_message,"status":self.okay}
                self._checkResults["headerChecks"]["checkDKIMAuthenticationResults"].append(results)
        
            else:
                result_message = f"Authentication-Results showed that DKIM couldn't pass provider's verification check -> {dkimAuthResults}"
                results = {"Checking":f"DKIM results in Authenication-Results -> header.s={dkimSelector} <-> header.i={dkimDomain}","condition1":dkimDomain+" (Domain)","condition2":dkimSelector+" (Selector)","results":result_message,"status":self.suspicious}
                self._checkResults["headerChecks"]["checkDKIMAuthenticationResults"].append(results)
    
    def checkDKIMVerifier(self,emailName:str):
        """
        It verifies DKIM signature using dkimverify from dkimpy

        Parameters:
        ----------
            emailName: *.eml name. Example: nytimes.eml
        """
        if not isinstance(emailName, str):
            raise AttributeError('checkDKIMVerifier() expects a string as first argument.')
    
        # Check if 'checkDKIMVerifier' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkDKIMVerifier")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkDKIMVerifier":[]})
        
        try:
            mail = BytesParser().parse(open(emailName, 'rb'))
            mailverification = dkim.verify(mail.as_bytes())

            if mailverification:
                result_message = "DKIM signature verified!"
                results = {"Checking":"Verifying manually the DKIM signature","condition1":self.NaN,"condition2":self.NaN,"results":result_message,"status":self.okay}
                self._checkResults["headerChecks"]["checkDKIMVerifier"].append(results)
            else:
                result_message = "DKIM signature wasn't verified!"
                results = {"Checking":"Verifying manually the DKIM signature","condition1":self.NaN,"condition2":self.NaN,"results":result_message,"status":self.suspicious}
                self._checkResults["headerChecks"]["checkDKIMVerifier"].append(results)
            
        except Exception as e:
            logging.error(f"[-] Couldn't read the {emailName} and verify its DKIM signature.")

    def checkDMARCLookUP(self,dmarcDomain:str):

        if not isinstance(dmarcDomain, str):
            raise AttributeError('checkDMARCLookUP() expects a string as first argument.')
        
        # Check if 'checkDMARCLookUP' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkDMARCLookUP")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkDMARCLookUP":[]})
        
        resolverAnswer=''
        if dmarcDomain and dmarcDomain !=None and dmarcDomain != "-":
            try:
                
                try:
                    resolverAnswer = dns.resolver.resolve(f"_dmarc.{dmarcDomain}", 'TXT')
                except Exception as e:
                    logging.error(f"Couldn't resolve _dmarc.{dmarcDomain} to retrieve the DMARC policy from TXT record. ")

                if resolverAnswer:   
                    query_name = resolverAnswer.qname
                    # List the holds answers in -> tuple
                    answer_txt_list_tuple = []
                    # List the holds answers in -> string
                    answer_txt_list_str = []

                    for x in resolverAnswer:
                        # Adding resolver responses to list -> tuple
                        answer_txt_list_tuple.append(x.strings)
                    
                    encoding = 'utf-8'
                    # Itterate through the answers
                    for ans in answer_txt_list_tuple:
                        # Every answer is tuple in bytes
                        # Convert the tuple to str
                        # Join the elements in the same tuple
                        res = ''.join([tups.decode(encoding) for tups in ans])
                        if res not in answer_txt_list_str:
                            answer_txt_list_str.append(res)
                    
                    if len(answer_txt_list_tuple) > 0:
                        for answer in resolverAnswer:
                            if answer and answer !="":
                                result_message = f"DMARC record is present for the domain -> {dmarcDomain}"
                                dmarc_signature = answer_txt_list_str
                                results = {"Checking":"DMARC Domain","condition1":dmarcDomain,"condition2":self.NaN,"results":result_message,"dmarc-signature":dmarc_signature,"status":self.okay}
                                self._checkResults["headerChecks"]["checkDMARCLookUP"].append(results)
                else:
                    result_message = f"DMARC record is not present for the domain -> {dmarcDomain}"
                    dmarc_signature = self.NaN
                    results = {"Checking":"DMARC Domain","condition1":dmarcDomain,"condition2":self.NaN,"results":result_message,"dmarc-signature":dmarc_signature,"status":self.suspicious}
                    self._checkResults["headerChecks"]["checkDMARCLookUP"].append(results)
                            
            except Exception as e:
                logging.error(f"[-] Function error checkDMARCLookUP() :: {e}")
        
        return resolverAnswer
    
    def checkDMARCVerifier(self,dkimDomain:str,spfDomain:str,dmarcDomain:str):

        """
        Parse and evaluate email authentication policy, to application supplied TXT RR, SPF and DKIM results.
        """
        
        # Check if 'checkDMARCVerifier' key exists in the dictionary
        keyExists = self.observables.deMailerZeusKeySearcher(self._checkResults["headerChecks"],"checkDMARCVerifier")
        if not keyExists:
            self._checkResults["headerChecks"].update({"checkDMARCVerifier":[]})

        # represent verified SPF and DKIM status
        aspf = dmarc.SPF(domain=spfDomain, result=dmarc.SPF_PASS)
        adkim = dmarc.DKIM(domain=dkimDomain, result=dmarc.DKIM_PASS)

        d = dmarc.DMARC()

        # parse policy TXT RR
        dmarcRecord = self.checkDMARCLookUP(dmarcDomain)

        if dmarcRecord and dmarcRecord !=None and dmarcRecord != "-":
            if spfDomain == dmarcDomain and dkimDomain == dmarcDomain:
                p = None
                try:
                    # Parse email authentication policy
                    p = d.parse_record(record=dmarcRecord, domain=dmarcDomain)
                except Exception as e:
                    logging.error(f"[-] Parsing error for DMARC record <> {dmarcRecord} and for domain <> {dmarcDomain}")
                
                if p and p != None:
                    # evaluate policy
                    r = d.get_result(p, spf=aspf, dkim=adkim)
                    # check result
                    if r.result == dmarc.POLICY_PASS:
                        _policyEvaluation = r.as_dict()
                        result_message = f"DMARC verified successfully for Domain <> {dmarcDomain}"
                        results = {"Checking":"Checking if DMARC record exists for the specified domain","condition1":dmarcDomain,"condition2":self.NaN,"results":result_message,"policy evaluation":_policyEvaluation,"status":self.okay}
                        self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)

                        spfPolicy = _policyEvaluation['record']['auth_results']['spf']
                        dkimPolicy = _policyEvaluation['record']['auth_results']['dkim']
                        headerFrom = _policyEvaluation['record']['identifiers']['header_from']
                        
                        if headerFrom != dmarcDomain:
                            result_message = f"DMARC's header.from <> {headerFrom} isn't equal with the queried DMARC domain <> {dmarcDomain}"
                            results = {"Checking":"Evaluates the values of DMARC domain with header.from","condition1":dmarcDomain,"condition2":headerFrom,"results":result_message,"dmarc-signature":dmarcRecord,"status":self.suspicious}
                            self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)
                                                    
                        if spfPolicy and dkimPolicy:
                            if spfPolicy['result'] == dkimPolicy['result']:
                                result_message = f"DKIM and SPF are equal! DKIM: {dkimPolicy['result']} and SPF: {spfPolicy['result']}"
                                results = {"Checking":"Compares the authenication results between DKIM and SPF","condition1":dkimPolicy['result'],"condition2":spfPolicy['result'],"results":result_message,"status":self.okay}
                                self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)
                            else:
                                result_message = f"DKIM and SPF are not equal! DKIM: {dkimPolicy['result']} and SPF: {spfPolicy['result']}"
                                results = {"Checking":"Compares the authenication results between DKIM and SPF","condition1":dkimPolicy['result'],"condition2":spfPolicy['result'],"results":result_message,"status":self.suspicious}
                                self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)
                
                if not p and p == None:         
                    if dmarc.POLICY_FAIL == 1:
                        result_message = f"DMARC policy failed for domain <> {dmarcDomain}"
                        results = {"Checking":"Validates the DMARC policy","condition1":dmarcDomain,"condition2":self.NaN,"results":result_message,"status":self.suspicious}
                        self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)

            else:
                result_message = f"SPF/DKIM domain <> {spfDomain}/{dkimDomain} isn't equal with DMARC domain <> {dmarcDomain}"
                results = {"Checking":"Compares the domain name value between the DKIM,SPF and DMARC","condition1":spfDomain+"/"+dkimDomain,"condition2":dmarcDomain,"results":result_message,"status":self.suspicious}
                self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)

        # If DMARC exists, compare the domain value with DKIM & SPF
        if dmarcDomain and dmarcDomain !=None and dmarcDomain != "-":
            if spfDomain != dmarcDomain:
                result_message = f"DMARC domain <> {dmarcDomain} doesn't match with the SPF domain <> {spfDomain}"
                results = {"Checking":"Checking if DMARC domain matches with the domain name from SPF results","condition1":spfDomain,"condition2":dmarcDomain,"results":result_message,"status":self.suspicious}
                self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)
            else:
                result_message = f"DMARC domain <> {dmarcDomain} matches with the SPF domain <> {spfDomain}"
                results = {"Checking":"Checking if DMARC domain matches with the domain name from SPF results","condition1":spfDomain,"condition2":dmarcDomain,"results":result_message,"status":self.okay}
                self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)
            
            if dkimDomain != dmarcDomain:
                result_message = f"DMARC domain <> {dmarcDomain} doesn't match with the DKIM domain <> {dkimDomain}"
                results = {"Checking":"Checking if DMARC domain matches with the domain name from DKIM results","condition1":dkimDomain,"condition2":dmarcDomain,"results":result_message,"status":self.suspicious}
                self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)
            else:
                result_message = f"DMARC domain <> {dmarcDomain} matches with the DKIM domain <> {dkimDomain}"
                results = {"Checking":"Checking if DMARC domain matches with the domain name from DKIM results","condition1":dkimDomain,"condition2":dmarcDomain,"results":result_message,"status":self.okay}
                self._checkResults["headerChecks"]["checkDMARCVerifier"].append(results)