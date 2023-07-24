from tabulate import tabulate
import pandas as pd
from termcolor import colored
from IPython.display import display
import json
import logging
import numpy as np
import tkinter as tk
import colors
import deMailer_global_vars
import os.path
from pathlib import Path

class deMailerPrinter:

    def __init__(self,format,enabled: bool =True):

        self.enabled = enabled
        self.format = format  # default = fancy_grid
        
        # https://github.com/scrtlabs/catalyst/issues/39
        #if os.environ.get('DISPLAY','') == '':
        #    os.environ.__setitem__('DISPLAY', ':0.0')
            
        self.root = tk.Tk()
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        self.column_multiplier = deMailer_global_vars.global_variable.COLUMN_WIDTH_MULTIPLIER

        # Get the filename from full file name
        fName = Path(deMailer_global_vars.global_variable.EMAIL_FILENAME).name
        # Remove extension
        fNameNoExtension = os.path.splitext(fName)[0]
        # Get current directory
        cwd = os.getcwd()
        # Make directory if doesn't exists
        makeDir = os.makedirs(cwd + '/' + 'html_report', exist_ok=True)
        # Report name
        report = f"{fNameNoExtension}_report.html"
        # Generate the full path
        self.reportFullPath = Path(cwd + '/html_report/' + report)
        deMailer_global_vars.global_variable.OUTPUT_TO_HTML_REPORT = self.reportFullPath

        # Delete the report if it's already exists
        htmlReportExists = Path(self.reportFullPath)
        if htmlReportExists.is_file():
            os.remove(self.reportFullPath)
        
        # Saves output from Tabulate in html
        self.HTML_CODE = ""        
    
    def finalReport(self):
        """
        Creates an HTML report which is similar as screen output.
        """
        YELLOW = colors.style.YELLOW
        RESET = colors.style.RESET
        CWD = deMailer_global_vars.global_variable.CWD
        SEP = deMailer_global_vars.global_variable.OS_SEP

        try:
            html_report = f"<header><link rel=\"stylesheet\" href=\"{CWD}{SEP}html_report.css\"></header><body>{self.HTML_CODE}</body>"
            f = open(self.reportFullPath,"w+")
            f.write(html_report)
            f.close()
            #print("[+] Report created successfully!")
        except Exception as e:
            logging.error(f"{YELLOW}[-] Funtion finalReport error::{e}{RESET}")

    def tabulateToHtml(self,title,tabulateData):
        
        self.HTML_CODE += f"{title}\n{tabulateData}\n"

    def maxTableWidth(self,columns:int):
        
        max_col_with = int(self.screen_width / (columns * self.column_multiplier))
        # Run forever!
        #self.root.mainloop()

        return max_col_with

    def dict_depth(self,dic, level = 1):
      
        str_dic = str(dic)
        counter = 0
        for i in str_dic:
            if i == "{":
                counter += 1
        return(counter)
    
    def printMailRoute(self,routingTable:dict,scanmode:int):

        if scanmode and scanmode not in (0,1):
            return
        
        print("[+] Tracing 'Received: from' [Routing] ...")
        title = "<h3>[+] Tracing 'Received: from' [Routing] ...</h3>"

        df = pd.DataFrame.from_dict(routingTable,orient='index')        

        #df["With"] = df["With"].astype(str).str.wrap(20)
        #df["By"] = df["By"].astype(str).str.wrap(30)
        #df["From"] = df["From"].astype(str).str.wrap(35)
        
        #for dkey, dvalue in df.items():
        #    df[dkey] = df[dkey].astype(str).str.wrap(30)
        
        relays_header = colored("Relays","green",attrs=["bold"])
        date_received_header = colored("Date Received (Ascending)","green",attrs=["bold"])
        received_from_header = colored("From","green",attrs=["bold"])
        received_by_header = colored("By","green",attrs=["bold"])
        received_with_header = colored("With","green",attrs=["bold"])
        envelope_from_header = colored("Envelope-From","green",attrs=["bold"])
        smtp_from_header = colored("Smtp.MailFrom","green",attrs=["bold"])
        header_from = colored("header.from","green",attrs=["bold"])

        relays_header_html = "Relays"
        date_received_header_html = "Date Received (Ascending)"
        received_from_header_html = "From"
        received_by_header_html = "By"
        received_with_header_html = "With"
        envelope_from_header_html = "Envelope-From"
        smtp_from_header_html = "Smtp.MailFrom"
        header_from_html = "header.from"
        
        cols_len = len([relays_header,date_received_header,received_from_header,received_by_header,received_with_header,envelope_from_header,smtp_from_header,header_from])
        max_col_width = self.maxTableWidth(cols_len)
        if max_col_width and max_col_width !=None:
            print(tabulate(df.sort_index(ascending=False),headers=[relays_header,date_received_header,received_from_header,received_by_header,received_with_header,envelope_from_header,smtp_from_header,header_from],tablefmt=self.format,maxcolwidths=max_col_width))
            html_output = tabulate(df.sort_index(ascending=False),headers=[relays_header_html,date_received_header_html,received_from_header_html,received_by_header_html,received_with_header_html,envelope_from_header_html,smtp_from_header_html,header_from_html],tablefmt="html",maxcolwidths=max_col_width)
            self.tabulateToHtml(title,html_output)
        else:
            print(tabulate(df.sort_index(ascending=False),headers=[relays_header,date_received_header,received_from_header,received_by_header,received_with_header,envelope_from_header,smtp_from_header,header_from],tablefmt=self.format))
            html_output = tabulate(df.sort_index(ascending=False),headers=[relays_header_html,date_received_header_html,received_from_header_html,received_by_header_html,received_with_header_html,envelope_from_header_html,smtp_from_header_html,header_from_html],tablefmt="html")
            self.tabulateToHtml(title,html_output)
        print("\n")
    
    def printFootprints(self,footprints:dict,scanmode:int):

        if scanmode and scanmode not in (0,2):
            return
        
        RED = colors.style.RED
        YELLOW = colors.style.YELLOW
        RESET = colors.style.RESET
        HIGHLIGHT = f"{RED};{RESET}"
        
        print("[+] Email footprints ...")
        title = "<h3>[+] Email footprints ...</h3>"
        df = pd.DataFrame.from_dict(footprints,orient='index').replace(r'\s+', ' ', regex=True).replace(r';', HIGHLIGHT, regex=True)

        # ekey->'Email Header name', evalue -> 'Email header value'.
        # Wrap the values of the table
        #for ekey,evalue in df.items():
        #    df[ekey] = df[ekey].str.wrap(90)
        
        header_value = colored("Header Value","green",attrs=["bold"])
        header_key = colored("Header Key","green",attrs=["bold"])

        header_value_html = "Header Value"
        header_key_html = "Header Key"

        # Footprints table has only 2 columns
        cols_len = 2
        max_col_width = self.maxTableWidth(cols_len)
        if max_col_width and max_col_width != None:
            print(tabulate(df,headers=[header_key,header_value],tablefmt=self.format,maxcolwidths=max_col_width)) #maxheadercolwidths
            html_output = tabulate(df,headers=[header_key_html,header_value_html],tablefmt="html",maxcolwidths=max_col_width)
            self.tabulateToHtml(title,html_output)
        else:
            print(tabulate(df,headers=[header_key,header_value],tablefmt=self.format))
            html_output = tabulate(df,headers=[header_key_html,header_value_html],tablefmt="html")
            self.tabulateToHtml(title,html_output)
        print("\n")
    
    def printEmails(self,emails:dict,scanmode:int):

        if scanmode and scanmode not in (0,3):
            return
        
        print("[+] Extracting E-mails ...")
        title = "<h3>[+] Extracting E-mails ...</h3>"

        # '_emails' list holds the email key in order to reindex with Pandas
        _emails = []
        # Adding a static header
        emailAddrheader = colored("E-mail Addresses","green",attrs=["bold"])
        emailAddrheader_html = "E-mail Addresses"
        headers = [emailAddrheader]
        headers_html = [emailAddrheader_html]

        for email in emails.keys():
            _emails.append(email)
        
        df = pd.DataFrame.from_dict(emails,orient='index').reindex(_emails)

        # Enumerate columns and add them to 'headers' list
        for column in list(df.columns):
            column_html = column
            column = colored(column,"green",attrs=["bold"])
            headers.append(column)
            headers_html.append(column_html)

        cols_len = len(headers)
        max_col_width = self.maxTableWidth(cols_len)
        if max_col_width and max_col_width != None:
            print(tabulate(df,headers,tablefmt=self.format,maxcolwidths=max_col_width))
            html_output = tabulate(df,headers_html,tablefmt="html",maxcolwidths=max_col_width)
            self.tabulateToHtml(title,html_output)
        else:
            print(tabulate(df,headers,tablefmt=self.format))
            html_output = tabulate(df,headers_html,tablefmt="html")
            self.tabulateToHtml(title,html_output)
        print("\n")

    def printUrls(self,urls:dict,scanmode:int):

        if scanmode and scanmode not in (0,4):
            return
        
        print("[+] Extracting URLs ...")
        title = "<h3>[+] Extracting URLs ...</h3>"
        # '_urls' list holds the url key in order to reindex with Pandas
        _urls = []
        # Adding a static header
        #urlheader = colored("Urls","green",attrs=["bold"])
        headers = []
        headers_html = []

        # Adding urls -> _urls
        for url in urls.keys():
            _urls.append(url)

        df = pd.DataFrame.from_dict(urls,orient='index').reindex(_urls).reset_index(drop=False)

        #for dkey, dvalue in df.items():
        #    df[dkey] = df[dkey].astype(str).str.wrap(150)

        # Enumerate columns and add them to 'headers' list
        for column in list(df.columns):
            if column == "index":
                column = colored("Urls","green",attrs=["bold"])
                column_html = "Urls"
                headers.append(column)
                headers_html.append(column_html)
            else:
                column_html = column
                column = colored(column,"green",attrs=["bold"])
                headers.append(column)
                headers_html.append(column_html)

        cols_len = len(headers)
        max_col_width = self.maxTableWidth(cols_len)
        if max_col_width and max_col_width != None:
            print(tabulate(df,headers,tablefmt=self.format,maxcolwidths=max_col_width))
            html_output = tabulate(df,headers_html,tablefmt="html",maxcolwidths=max_col_width)
            self.tabulateToHtml(title,html_output)
        else:
            print(tabulate(df,headers,tablefmt=self.format))
            html_output = tabulate(df,headers_html,tablefmt="html")
            self.tabulateToHtml(title,html_output)
        print("\n")
    
    def printGeoIP(self,geoIP:dict,scanmode:int):

        if scanmode and scanmode not in (0,5):
            return
        
        print("[+] GeoIP Location ...")
        title = "<h3>[+] GeoIP Location ...</h3>"
        # '_geoIP' list holds the url key in order to reindex with Pandas
        _geoIP = []
        # Adding a static header
        geoIPheader = colored("IP Address","green",attrs=["bold"])
        geoIPheader_html = "IP Address"
        headers = [geoIPheader]
        headers_html = [geoIPheader_html]

        for geoip in geoIP.keys():
            _geoIP.append(geoip)
        
        df = pd.DataFrame.from_dict(geoIP,orient='index').reindex(_geoIP)

        # Enumerate columns and add them to 'headers' list
        for column in list(df.columns):
            column_html = column
            column = colored(column,"green",attrs=["bold"])
            headers.append(column)
            headers_html.append(column_html)

        cols_len = len(headers)
        max_col_width = self.maxTableWidth(cols_len)
        if max_col_width and max_col_width != None:
            print(tabulate(df,headers,tablefmt=self.format,maxcolwidths=max_col_width))
            html_output = tabulate(df,headers_html,tablefmt="html",maxcolwidths=max_col_width)
            self.tabulateToHtml(title,html_output)
        else:
            print(tabulate(df,headers,tablefmt=self.format))
            html_output = tabulate(df,headers_html,tablefmt="html")
            self.tabulateToHtml(title,html_output)

        print("\n")
    
    def printDnsLookUp(self,dnsLookUp:dict,scanmode:int):

        if scanmode and scanmode not in (0,6):
            return
                
        print("[+] DNS LookUp ...")
        title = "<h3>[+] DNS LookUp ...</h3>"

        # '_dnsLookUp' list holds the url key in order to reindex with Pandas
        _dnsLookUp = []
        # Adding a static header
        dnsLookUpheader = colored("Domain Name","green",attrs=["bold"])
        dnsLookUpheader_html = "Domain Name"
        headers = [dnsLookUpheader]
        headers_html = [dnsLookUpheader_html]

        for dnslookup in dnsLookUp.keys():
            _dnsLookUp.append(dnslookup)
        
        df = pd.DataFrame.from_dict(dnsLookUp,orient='index').reindex(_dnsLookUp)
        
        #for dkey, dvalue in df.items():
        #    df[dkey] = df[dkey].astype(str).str.wrap(30)

        # Enumerate columns and add them to 'headers' list
        for column in list(df.columns):
            column_html = column
            column = colored(column,"green",attrs=["bold"])
            headers.append(column)
            headers_html.append(column_html)

        cols_len = len(headers)
        max_col_width = self.maxTableWidth(cols_len)
        if max_col_width and max_col_width != None:
            print(tabulate(df,headers,tablefmt=self.format,maxcolwidths=max_col_width))
            html_output = tabulate(df,headers_html,tablefmt="html",maxcolwidths=max_col_width)
            self.tabulateToHtml(title,html_output)
        else:
            print(tabulate(df,headers,tablefmt=self.format))
            html_output = tabulate(df,headers_html,tablefmt="html")
            self.tabulateToHtml(title,html_output)
        print("\n")

    def printWhoIsLookUp(self,whoisLookUp:dict,scanmode:int):

        if scanmode and scanmode not in (0,7):
            return
        
        print("[+] Whois LookUp ...")
        title = "<h3>[+] Whois LookUp ...</h3>"
        # '_whoisLookUp' list holds the url key in order to reindex with Pandas
        _whoisLookUp = []
        # Adding a static header
        whoisLookUpheader = colored("Domain/IP","green",attrs=["bold"])
        whoisLookUpheader_html = "Domain/IP"
        headers = [whoisLookUpheader]
        headers_html = [whoisLookUpheader_html]

        for whoislookup in whoisLookUp.keys():
            _whoisLookUp.append(whoislookup)

        df = pd.DataFrame.from_dict(whoisLookUp,orient='index').reindex(_whoisLookUp)

        #df['name_servers'] = df['name_servers'].astype(str).str.wrap(30)
        #df['updated_date'] = df['updated_date'].astype(str).str.wrap(30)
        #df['domain_registrar'] = df['domain_registrar'].astype(str).str.wrap(10)

        #for dkey, dvalue in df.items():
            # dkey -> Are the headers of the table e.g. Domain/IP, registrant_org, domain_registrar etc.
            # dvalue -> Is Panda Series which is a list.
        #    for value in dvalue:
                # We do this to exclude Boolean for checks. Otherwise we get an Error -> 'ValueError: could not convert 'True' to float'
        #        if isinstance(value,list):
        #            df[dkey] = df[dkey].astype(str).str.wrap(20)
                
        #        if isinstance(value,str):
        #            df[dkey] = df[dkey].astype(str).str.wrap(20)

        # Enumerate columns and add them to 'headers' list
        for column in list(df.columns):
            column_html = column
            column = colored(column,"green",attrs=["bold"])
            headers.append(column)
            headers_html.append(column_html)

        cols_len = len(headers)
        max_col_width = self.maxTableWidth(cols_len)
        if max_col_width and max_col_width != None:
            print(tabulate(df,headers,tablefmt=self.format,maxcolwidths=max_col_width))
            html_output = tabulate(df,headers_html,tablefmt="html",maxcolwidths=max_col_width)
            self.tabulateToHtml(title,html_output)
        else:
            print(tabulate(df,headers,tablefmt=self.format))
            html_output = tabulate(df,headers_html,tablefmt="html")
            self.tabulateToHtml(title,html_output)
        print("\n")
    
    def printObservables(self,observables:dict,scanmode:int):

        if scanmode and scanmode not in (0,8):
            return
        
        observables2={}
        print("[+] Printing Observables ...")
        title = "<h3>[+] Printing Observables ...</h3>"
        # '_observables' list holds all observables (IPs/Domains/Emails) in order to reindex with Pandas
        _observables = []
        # Adding a static header
        #observableheader = colored("Observables","green",attrs=["bold"])
        headers = []
        headers_html = []

        # Iterate through initial dict to unfold the keys under root keys, which are ips, domains, emails
        for obsKey,obsValue in observables.items():
            observables2.update(observables[obsKey])

        # Add all observables to a list 
        for observable in observables2.keys():
            _observables.append(observable)

        df = pd.DataFrame.from_dict(observables2,orient='index').reindex(_observables).reset_index(drop=False)

        #for dkey, dvalue in df.items():
        #    if dkey == "index":
        #        df[dkey] = df[dkey].astype(str).str.wrap(50)
            
        vt_last_analysis_stats_depth = None
        # Enumerate columns and add them to 'headers' list
        for column in list(df.columns):
            if column == "index":
                column = colored("Observables","green",attrs=["bold"])
                column_html = "Observables"
                headers.append(column)
                headers_html.append(column_html)
            
            elif column in ['vt_analysis_stats']:
                
                # Check the depth of 'vt_last_analysis_stats'
                # When has 1 depth then there are NO atributes key and most probably it contains scanning results.
                # Example: {'vt_last_analysis_stats': {'harmless': 63, 'malicious': 7, 'suspicious': 1, 'undetected': 15, 'timeout': 0}}
                
                vt_last_analysis_stats_values = df['vt_analysis_stats'].values
                for cell in vt_last_analysis_stats_values:
                    vt_last_analysis_stats_depth = self.dict_depth(cell)
                    indexList = df[df['vt_analysis_stats'].values == cell].index.values

                    if len(indexList) > 0:
                        # Unfold multi-index from list -> tuple
                        for index in indexList:
                            # Create 'depth' column and add the depth of the dict
                            df.at[index,'depth'] = vt_last_analysis_stats_depth
                            # Fill NaN with 0
                            df['depth'] = df['depth'].replace(np.nan, 0)
                            # Convert float -> int
                            df['depth'] = df['depth'].astype(int)

                # Depth of dictionary inside 'vt_last_analysis_stats'
                depth_max = df['depth'].max()
                
                # Check the depth of 'vt_last_analysis_stats'
                # When has 1 depth then there are NO atributes key and most probably it contains scanning results.
                # Example: {'vt_last_analysis_stats': {'harmless': 63, 'malicious': 7, 'suspicious': 1, 'undetected': 15, 'timeout': 0}}
                if depth_max and depth_max != None and depth_max == 1:
                    column_html = column
                    column = colored(column,"green",attrs=["bold"])
                    headers.append(column)
                    headers_html.append(column_html)

                # When has >1 depth then it has atributes key and in depth dict.
                # Example: {'vt_last_analysis_stats'{0:{'attributes':{ .... }}
                # Drop that column
                elif depth_max and depth_max != None and depth_max > 1:
                    df.drop(columns=['vt_analysis_stats'],inplace=True)
                
                df.drop(columns=['depth'],inplace=True)

            elif column != "index" and column not in ['vt_analysis_stats']:
                column_html = column
                column = colored(column,"green",attrs=["bold"])
                headers.append(column)
                headers_html.append(column_html)

        cols_len = len(headers)
        max_col_width = self.maxTableWidth(cols_len)
        if max_col_width and max_col_width != None:
            print(tabulate(df,headers,tablefmt=self.format,maxcolwidths=max_col_width))
            html_output = tabulate(df,headers_html,tablefmt="html",maxcolwidths=max_col_width)
            self.tabulateToHtml(title,html_output)
        else:
            print(tabulate(df,headers,tablefmt=self.format))
            html_output = tabulate(df,headers_html,tablefmt="html")
            self.tabulateToHtml(title,html_output)
        print("\n")

    def printVTRelations(self,observables:dict,type:str):
        """
        type: ips, domains, urls, emails
        """
        #print("[+] VirusTotal Relations ...")
        title = "<h3>[+] VirusTotal ...</h3>"
        # Columns that I care about
        _columns = [
                    'Assets',
                    'IsPrivate',
                    'IsWhitelisted',
                    'Datasource',
                    'last_analysis_stats',
                    'last_analysis_stats.malicious',
                    'last_analysis_stats.attributes.names',
                    'last_analysis_stats.attributes.type_tags',
                    'last_analysis_stats.attributes.host_name',
                    'last_analysis_stats.attributes.ip_address_last_analysis_stats',
                    'last_analysis_stats.attributes.ip_address_last_analysis_stats.malicious',
                    'last_analysis_stats.attributes.host_name_last_analysis_stats',
                    'last_analysis_stats.attributes.host_name_last_analysis_stats.malicious',
                    'last_analysis_stats.attributes.popular_threat_classification.suggested_threat_label'
                ]
        
        columns_renamed = {

                'Assets':'Observables',
                'IsPrivate':'IsPrivate',
                'IsWhitelisted':'IsWhitelisted',
                'Datasource':'Datasource',
                'last_analysis_stats':'Malicious score (Asset)',
                'last_analysis_stats.malicious':'Malicious',
                'last_analysis_stats.attributes.names':'Names',
                'last_analysis_stats.attributes.type_tags':'Tags',
                'last_analysis_stats.attributes.host_name':'Hostname',
                'last_analysis_stats.attributes.ip_address_last_analysis_stats':'IP Stats',
                'last_analysis_stats.attributes.ip_address_last_analysis_stats.malicious':'Malicious score (IP)',
                'last_analysis_stats.attributes.host_name_last_analysis_stats':'Hostname Stats',
                'last_analysis_stats.attributes.host_name_last_analysis_stats.malicious':'Malicious score (Hostname)',
                'last_analysis_stats.attributes.popular_threat_classification.suggested_threat_label':'Label'

            }
        
        pd.set_option('mode.chained_assignment', None)
        df1 = pd.DataFrame(observables,columns=[type])
        df2 = pd.DataFrame(df1)
        unstack= df2.unstack()
        df3 = pd.DataFrame(unstack.values.tolist(), index=unstack.index)
        df3['depth']=''

        df4=pd.DataFrame()
        vt_last_analysis_stats_depth = None
        if 'last_analysis_stats' in df3.columns.tolist():
            # Check the depth of 'vt_last_analysis_stats'
            # When has 1 depth then there are NO atributes key and most probably iit contains scanning results.
            # Example: {'harmless': 63, 'malicious': 7, 'suspicious': 1, 'undetected': 15, 'timeout': 0}
            vt_last_analysis_stats_depth = self.dict_depth(df3['last_analysis_stats'])

            vt_last_analysis_stats_values = df3['last_analysis_stats'].values
            for cell in vt_last_analysis_stats_values:
                vt_last_analysis_stats_depth = self.dict_depth(cell)
        
                # Returns multindex to list
                # Example: [('ips', '177.153.11.48')]
                indexList = df3[df3['last_analysis_stats']==cell].index.values
        
                if len(indexList) > 0:
                    # Unfold multi-index from list -> tuple
                    for index in indexList:
                        df3.at[index,'depth'] = vt_last_analysis_stats_depth
                else:
                    df3['depth'] = df3['depth'].replace('',0)

        # Copy values to df4
        df4 = pd.DataFrame(df3)
        # Depth of dictionary inside 'vt_last_analysis_stats'
        depth_max = df4['depth'].max()

        if depth_max and depth_max != None and depth_max > 1:
            # Set new df4
            df4 = pd.DataFrame(df3).drop(columns=['last_analysis_stats'])
            df4.drop(columns=['depth'])
            df4['last_analysis_stats']=''

            if len(df4) > 0:
                # Holds the 'attributes' keys of every IP/Domain/URL etc 
                for k1,v1 in  df3.items():
                    #print(f"{k1} <->{v1}")
                    for k2,v2 in v1.items():
                        #print(f"{k2} <->{v2}")
                        if isinstance(v2,dict):
                            series = []
                            for k3,v3 in v2.items():
                                #print(f"{k2[1]} <-> {v3}")

                                for i in range(len(df4.index)):
                                    #print(df4.index)
                                    #print(df4.index[i])
                                    for j in range(len(df4.index[i])):
                                        #print(df4.index[i][j])
                                        if df4.index[i][j] == k2[1]:
                                            #print(f"{k2[1]} <-> {v3}")
                                            series.append(v3)

                                        if df4.index[i][1] == k2[1]:
                                            df4.at[df4.index[i],'last_analysis_stats'] = series
            
            df4.reset_index(inplace=True)
            df4.rename(columns={'level_1':'Assets'},inplace=True)
            df4.drop(columns=['level_0'],inplace=True)
            exploded_df = df4.explode('last_analysis_stats')

            json_struct = json.loads(exploded_df.to_json(orient="records"))
            df_flat = pd.json_normalize(json_struct)
            #_vt_keys = df_flat.columns.tolist()

            # Filter Dataframe columns. If a column doesn't exist in '_columns' then removed it from the dataframe
            df_flat_new = df_flat[df_flat.columns.intersection(_columns)]
            # Rename Dataframe columns.
            df_flat_new.columns = df_flat_new.columns.to_series().map(columns_renamed)
            
            # Give a color to column names
            headers = []
            headers_html = []
            for column in df_flat_new.columns.tolist():
                column_html = column
                column = colored(column,"green",attrs=["bold"])
                headers.append(column)
                headers_html.append(column_html)

            # Wrap text
            #try:
            #    for dkey, dvalue in df_flat_new.items():
            #        df_flat_new[dkey] = df_flat_new[dkey].astype(str).str.wrap(40)
            #except Exception as e:
            #    logging.error(f"[-] Function printVTRelations() error :: {e}")

            print(tabulate(df_flat_new,headers,tablefmt=self.format))
        
        # Jump here there aren't nested dictionaries inside the 'vt_last_analysis_stats'
        elif depth_max and depth_max != None and depth_max <= 1:

            df4.reset_index(inplace=True)
            df4.rename(columns={'level_1':'Assets'},inplace=True)
            df4.drop(columns=['level_0'],inplace=True)
            df4.drop(columns=['depth'],inplace=True)

            df_flat_new = pd.DataFrame(df4)
            # Give a color to column names
            headers = []
            headers_html = []
            for column in df_flat_new.columns.tolist():
                column_html = column
                column = colored(column,"green",attrs=["bold"])
                headers.append(column)
                headers_html.append(column_html)
            
            # Wrap text
            #try:
            #    for dkey, dvalue in df_flat_new.items():
            #        df_flat_new[dkey] = df_flat_new[dkey].astype(str).str.wrap(90)
            #except Exception as e:
            #    logging.error(f"[-] Function printVTRelations() error :: {e}")

            cols_len = len(headers)
            max_col_width = self.maxTableWidth(cols_len)
            if max_col_width and max_col_width != None:
                print(tabulate(df_flat_new,headers,tablefmt=self.format,maxcolwidths=max_col_width))
                html_output = tabulate(df_flat_new,headers_html,tablefmt="html",maxcolwidths=max_col_width)
                self.tabulateToHtml(title,html_output)
            else:
                print(tabulate(df_flat_new,headers,tablefmt=self.format))
                html_output = tabulate(df_flat_new,headers_html,tablefmt="html")
                self.tabulateToHtml(title,html_output)
        
        else:
            print("[-] Function printVTRelations() :: vt_last_analysis_stats_depth variable has 'None' value")
            
    def printHeaderChecks(self,headerChecks:dict,scanmode:int):

        if scanmode and scanmode not in (0,9):
            return
        
        print("[+] Checking Headers ...")
        title = "<h3>[+] Checking Headers ...</h3>"
        df = pd.DataFrame.from_dict(headerChecks,orient='index').T.explode('headerChecks').reset_index(drop=True)
        df.dropna(inplace=True)

        nestedDictsToList = []
        headers = []
        headers_html = []
        for index,values in df.itertuples():
            nestedDictsToList.append(values)

        df2 = pd.DataFrame(nestedDictsToList)
        
        #for dkey, dvalue in df2.items():
        #    df2[dkey] = df2[dkey].astype(str).str.wrap(30)

        # Enumerate columns and add them to 'headers' list
        for column in list(df2.columns):
            column_html = column
            column = colored(column,"green",attrs=["bold"])
            headers.append(column)
            headers_html.append(column_html)

        cols_len = len(headers)
        max_col_width = self.maxTableWidth(cols_len)
        if max_col_width and max_col_width != None:
            print(tabulate(df2,headers,tablefmt=self.format,maxcolwidths=max_col_width))
            html_output = tabulate(df2,headers_html,tablefmt="html",maxcolwidths=max_col_width)
            self.tabulateToHtml(title,html_output)
        else:
            print(tabulate(df2,headers,tablefmt=self.format))
            html_output = tabulate(df2,headers_html,tablefmt="html")
            self.tabulateToHtml(title,html_output)
        print("\n")