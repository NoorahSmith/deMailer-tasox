import imgkit
import outlookmsgfile
from msg_parser import MsOxMessage
from pathlib import Path
import logging
import os
from termcolor import colored
import deMailer_global_vars
import re
from bs4 import BeautifulSoup
import colors

class deMailerMsg2EmlConverter:
    
    def __init__(self):

        """
        This class converts an MSG into EML
        
        Parameters
        ----------
        Doesn't get any values
        """

        self.NaN = "-"

    def convertMSGtoEMLv1(self,file: str) ->str:

        """
        Converts an MSG into EML with 'MsOxMessage' using the 3rd party library 'msg_parser'

        Parameters
        ----------
        Value: str
            Full path of the MSG file
        
        Return
        ------
        EML file name: str
        """

        try:
            msg_obj = MsOxMessage(file)
            #json_string = msg_obj.get_message_as_json()
            msg_properties_dict = msg_obj.get_properties()
        except Exception as e:
            raise Exception(f'[-] Something went during conversion from MSG->EML')

        fout = file.replace(".msg",".eml")
        fo = open(fout, "w")

        for k, v in msg_properties_dict.items():
            fo.write(str(k) + ': '+ str(v)+'\n')
        
        fo.close()

        return fo.name

    def convertMSGtoEMLv2(self,file):

        """
        Converts an MSG into EML with the 3rd party library 'outlookmsgfile'

        Parameters
        ----------
        Value: str
            Full path of the MSG file
        
        Return
        ------
        EML file name: str
        """

        
        try:
            eml = outlookmsgfile.load(file)
        except Exception as e:
            raise Exception(f'{colors.style.RED}[-] Something went during conversion from MSG->EML{colors.style.RESET}')

        fout = file.replace(".msg",".eml")
        fo = open(fout, "w+")

        for emlContaints in eml.walk():
            fo.write(str(emlContaints))
        
        fo.close()

        return fo.name

class deMailerBodyConverter:

    def __init__(self):

        """
        This class converts the Body of an e-mail into IMG or Text

        Parameters
        ----------
        Doesn't get any values
        """

        self.NaN = "-"
    
    def removeEmptyTags(self,html):
        """
        Reads the body of the email and removes tags without properties and empty contents to clear the emal body
        """
        f = open(html,"r+")
        html_object = f.read()
        soup = BeautifulSoup(html_object, "lxml")

        for x in soup.find_all():
            if len(x.get_text(strip=True)) == 0 and len(x.attrs) == 0:
                x.extract()
        # Convert BeautifulSoup object
        soup = str(soup)
        try:
            # Strip New Lines
            soup = re.sub(r'\n{2,}','\n\n',soup)
        except Exception as e: pass

        return soup

    def body2img(self,body: str, enabled=True):

        """
        Gets the body of an e-mail and convert it into image, and saves in under the `/BODY2IMG/` folder.
        To convert body into image, it uses a 3rd party library that is called imgkit.
        """

        cwd = os.getcwd()
        fileName = "body2img.png"
        os.makedirs(cwd + '/' + 'BODY2IMG', exist_ok=True)
        fileFullPath = Path(cwd + "/BODY2IMG/" + fileName)
        fileFullPathSTR = str(fileFullPath)

        try:
            options = {'quiet': ''}
            imgkit.from_string(body, fileFullPathSTR,css='imgkit.css',options=options)
            print(colored(f"[+] Body converted to image successfully and saved under: {fileFullPath}","yellow",attrs=["bold"]))

        except Exception as e:
            logging.error(f':: Error raised during conversion of body to image :: {e}')
    
    def body2txt(self,body: str, enabled=True):
        
        """
        Gets the body of an e-mail and convert it into text, and saves in under the `/BODY2TXT/` folder.
        It saves the body in two formats. The one is the actual text 'body2txt.txt' and the second is modified 'body2txt_as_html.'
        """
        CWD = deMailer_global_vars.global_variable.CWD
        SEP = deMailer_global_vars.global_variable.OS_SEP

        fileName2 = "body2txt.txt"
        fileName3 = "body2txt_as_html.txt"
        fileName4 = "body2txt_stripped.txt"
        os.makedirs(f"{CWD}{SEP}BODY2TXT", exist_ok=True)
        fileFullPath2 = Path(f"{CWD}{SEP}BODY2TXT{SEP}{fileName2}")
        fileFullPath3 = Path(f"{CWD}{SEP}BODY2TXT{SEP}{fileName3}")    
        fileFullPath4 = Path(f"{CWD}{SEP}BODY2TXT{SEP}{fileName4}")        
        
        try:
            with open(fileFullPath2, 'w+') as outfile:
                try:
                    body = re.sub(r'\n{2,}','\n\n',body)
                except Exception as e: pass

                outfile.write(body)
            outfile.close()

            fr = open(fileFullPath2,"r")

            try:
                # remove empty tags and without properties
                fr_stripped = self.removeEmptyTags(fileFullPath2)
                with open(fileFullPath4, 'w+') as outfile:
                    outfile.write(fr_stripped)
                outfile.close()
            except Exception as e:
                logging.error(f"{colors.style.YELLOW}[-] Function body2txt() error ::{e}{colors.style.RESET}")

            with open(fileFullPath3, "w+") as e:
                for line in fr.readlines():
                    e.write("<pre>" + line + "</pre>")
            fr.close()
            e.close()
            
            fr2 = open(fileFullPath3,"r")
            body = fr2.read()
            #self.body2img(body)
            #print(colored(f"[+] Body converted to text successfully and saved under: {fileFullPath2}","yellow",attrs=["bold"]))
            deMailer_global_vars.global_variable.EMAIL_BODY_TO_TEXT_FULL_PATH = fileFullPath4

        except Exception as e:
            logging.error(f'::Something went wrong while creating `body2txt.txt`:: {e}')

class deMailerMiscConverter:
    def __init__(self,val):

        self.val = val

    def listToLowerCase(self):
        
        """
        Converts a list of string values to Lowercase
        
        Parameters
        ----------
        Doesn't take any values
        
        Return
        ------
        lowerCaseList: list
            A list with strings in Lower Case
        """
        
        # Converts a list a values to LowerCase
        lowerCaseList = list((map(lambda x: x.lower(), self.val)))
        
        return lowerCaseList
    
    def strToLowerCase(self):
        
        """
        Converts string to Lowercase
        
        Parameters
        ----------
        Doesn't take any values
        
        Return
        ------
        lowerCaseList: list
            A string in Lower Case
        """
        
        # Converts a string to Lower Case
        lowerCaseStr = str(self.val).lower()
        
        return lowerCaseStr