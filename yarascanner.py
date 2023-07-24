import yara
from pathlib import Path
import os

class deMailerYaraScanner:
    
    def __init__(self,enabled: bool =True):

        self.enabled = True


    def console(self,message):
            """
            https://yara.readthedocs.io/en/stable/yarapython.html
            """
            if message['matches'] == True:
                print(f"Matches: {message['matches']}")
                print(f"Rule Name: {message['rule']}")
                print(f"Strings: {message['strings']}")
                print("=====")

    def fileManager(self,filePath):
        """
        https://www.pythoncheatsheet.org/cheatsheet/file-directory-path
        """
        dir = ''
        file = ''
        if filePath:
            # Check if is file
            if os.path.isfile(filePath):
                file = filePath
            # Check if is dir    
            elif not os.path.isfile(filePath):
                dir = filePath
            
        return dir,file

    def yaraScanner(self,file,dir,emailFile):

        rules = ''
        if file and not dir:
            rules = yara.compile(filepaths={'namespace1':file})

        elif dir and not file:
            _rules = {}
            c = 1
            # Listing directory
            for f in Path(dir).iterdir():
                _rules.update({'namespace'+str(c):f.as_posix()})
                c +=1
            try:
                rules = yara.compile(filepaths=_rules)
            except Exception as e: pass

        if rules:
            matches = rules.match(emailFile,callback=self.console)

        return matches