![logo](logo.png)

# Description

> deMailer is a python3 tool that breaks-down an email message into components and extracts useful indicators that can be used for collecting intelligence to support a decision.

## What deMailer is NOT

> At this point, I would like to highlight what is not in the scope of this tool. First and most importantly, deMailer isn't a replacement of any other email analysis & reporting tool that you currently have in your disposal and was never created with that in mind. Consider this as another one tool that could help you against the fight with phishing emails. It will extract attachments but no further actions will be taken. That means, users have to use different tools to investigate and analyze the extracted attachments. To assess objectively the output of the tool as well as dinstinguise the expected from the unexpected, analysts must have a basic understanding of email headers.

## Setup environment

deMailer can run eiher by cloning this repo and installing its dependencies with ```requirements.txt``` or pulling deMailer's docker image from DockerHub (https://hub.docker.com/r/tasox/demailer). Both options will be covered in this documentation:

- [Docker setup](#docker-setup)
- [Manual setup](#manual-setup) 

### Docker setup

> To run deMailer successfully as a docker image, you have first to download (pull) it from my [docker hub repository](https://hub.docker.com/r/tasox/demailer). deMailer needs access to your local X server in order to print the results to your screen. For this reason, you have to enable ```xhost```[1] for the root user with the command ```xhost +SI:localuser:root```. When you finish your investigation restore the X screen access control to normal with ```xhost -```. After pulling deMailer and adding the ```localuser:root``` to access control list the final step is to run deMailer container in interactive mode:

**Download AMD64/ARM64**
```
sudo docker run -it -e DISPLAY=$DISPLAY --network=host -v /tmp/.X11-unix:/tmp/.X11-unix tasox/demailer:linux-amd64-latest
sudo docker run -it -e DISPLAY=$DISPLAY --network=host -v /tmp/.X11-unix:/tmp/.X11-unix tasox/demailer:linux-arm-latest
```

**Execution AMD64 Version:**
```
sudo docker run -it -e DISPLAY=$DISPLAY --network=host -v /tmp/.X11-unix:/tmp/.X11-unix tasox/demailer:linux-amd64-latest
```

**Execution ARM64 Version:**
```
sudo docker run -it -e DISPLAY=$DISPLAY --network=host -v /tmp/.X11-unix:/tmp/.X11-unix tasox/demailer:linux-arm-latest
```

**Note:** If you use this option, you'll not need to install anything in your host.

Now, you're inside deMailer's docker image which also includes one malicious email sample.

```
┌──(parallels㉿kali-linux-2021-3)-[~]
└─$ sudo docker run -it -e DISPLAY=$DISPLAY --network=host -v /tmp/.X11-unix:/tmp/.X11-unix tasox/demailer:latest

root@2aab7c356136:/home/deMailer# python3 deMailer.py -f email_samples/2023-03-17-Emotet-E5-malspam-1644-UTC.eml
```


### Manual setup

This setup option requires the installation of various dependenicies but first install ```pandas```:

```
pip install pandas==1.5.3
apt-get install python3-tk
```

Then install all the other requirements with:

```
pip install -r requirements.txt
```


Execute the help command to verify that all the required dependencies installed and no errors returned:

```
python3 deMailer.py -h

```

---

## Usage
> The help output was grouped into six categories: ```VirusTotal```, ```Yara```, ```Display modes```, ```Output```, ```Exclude from scanning``` which I'm going to describe later and provide some examples. By default, deMailer, is not procceeding with further scanning when ```private IPs``` are identified - it will extract them, however is not going to use them for information collection. 

- [Virus Total](#virus-total)
- [Yara](#Yara)
- [Display modes](#display-modes)
- [Output](#manual-checks)
- [Exclude from scanning](#exclude-from-scanning)



```
[*] Usage: demailer.py -f <*.msg/eml> <argument>

options:
  -h, --help            show this help message and exit

Required arguments:
  -f FILE, --file FILE  Provide an EML/MSG file.

VirusTotal:
  -vtapi VTAPI          Scanning observables with VirusTotal [API key is needed].
  -X, --extensive       Enable VirusTotal Extensive scan.

Yara:
  -y YARA, --yara YARA  Yara rule(s) directory or file.

Display modes:
  -m {0,1,2,3,4,5,6,7,8,9}, --mode {0,1,2,3,4,5,6,7,8,9}
                        Print to screen your specified mode (Default:0), 
                            [0]=All,[1]=Routing table,[2]=Footprints,[3]=Email addresses,[4]=URLs,[5]=GeoIP,[6]=DNS Lookup,[7]=WhoIs,[8]=Observables,[9]=Checks

Output:
  -s SAVEJSON, --saveJSON SAVEJSON
                        Save results to JSON file.
  --table_format {plain,simple,github,grid,simple_grid,rounded_grid,heavy_grid,mixed_grid,double_grid,fancy_grid,outline,simple_outline,rounded_outline,heavy_outline,mixed_outline,double_outline,fancy_outline,pipe,orgtbl,asciidoc,jira,presto,pretty,psql,rst,mediawiki,moinmoin,youtrack,html,unsafehtml,latex,latex_raw,latex_booktabs,latex_longtable,textile,tsv}
                        Choose output table format (Default: fancy_grid). More info can be found: https://pypi.org/project/tabulate/

Exclude from scanning:
  --exclude_ips EXCLUDE_IPS
                        Exclude an IP(s) or CIDR from scanning.
  --exclude_domains EXCLUDE_DOMAINS
                        Exclude an Domain(s) from scanning.
  --exclude_emails EXCLUDE_EMAILS
                        Exclude an Email(s) from scanning.

Version number:
  --version             show program's version number and exit
```

---

### Basic usage

> The ```-f/--file``` flag takes as input an ```*.msg``` or ```*.eml```. If the user provided an email in ```.*msg``` format then it converted into ```*.eml``` with ```outlookmsgfile.py```

```
python3 deMailer.py -f <*.eml/*.msg>
```

---

## Virus Total

> You can collect intelligence about extracted ```IPs``` and ```Domains``` from VirusTotal (VT) if you provide your VT API as input and you also have the option to choose between a basic (by default) or an extensive scan. To enable the extensive scan, you must use both ```-vtapi``` and ```-X``` flags. 

**Note**: deMailer is requesting only data and it doesn't submitting any data to VT. As already mentioned above, the tool excludes by default all private IPs. Below is an VT API list that is used.


| API | VT Description | Mode |
--- | --- | ---
https://www.virustotal.com/api/v3/ip_addresses/{ip_address} | Get an IP address report (https://developers.virustotal.com/reference/ip-info) | Basic scan
https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/resolutions | The resolutions relationship returns a list of past and current domain resolutions for a IP address. (https://developers.virustotal.com/reference/ip-resolutions) | Extensive scan
https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/communicating_files | The communicating_files relationship lists all files presenting any sort of traffic to the given IP address at some point of its execution. (https://developers.virustotal.com/reference/ip-communicating_files) | Extensive scan
https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/referrer_files | The referrer_files relationship returns a list of files containing the given IP address on its strings. (https://developers.virustotal.com/reference/ip-referrer_files) | Extensive scan
https://www.virustotal.com/api/v3/domains/{domain} | Get a Domain report (https://developers.virustotal.com/reference/domain-info) | Basic scan
https://www.virustotal.com/api/v3/domains/{domain}/resolutions | The resolutions relationship returns a list of past and current IP resolutions for a given domain or subdomain. (https://developers.virustotal.com/reference/domain-resolutions) | Extensive scan
https://www.virustotal.com/api/v3/domains/{domain}/communicating_files | The communicating_files relationship lists all files presenting any sort of traffic to the given domain at some point of its execution. (https://developers.virustotal.com/reference/domain-communicating_files) | Extensive scan
https://www.virustotal.com/api/v3/domains/{domain}/referrer_files | The referrer_files relationship returns a list of files containing the given domain on its strings. (https://developers.virustotal.com/reference/domain-referrer_files) | Extensive scan

**Note:** I have created similar requests for URLs but is not currently enabled

### Basic scan

```
python3 deMailer.py -f <*.eml/*.msg> -vtapi <API>
```
![VirusTotal basic scan](images/vt_basic_scan.png)

### Extensive scan

```
python3 deMailer.py -f <*.eml/*.msg> -vtapi <API> -X
```

![VirusTotal extensive scan](images/vt_extensive_scan.png)

---

## Yara
It is possible to scan the email message with a single yara rule or a directory the contains multiple rules.

**Note:** Not every public Yara rule is compatible for email scanning. 

```
python3 deMailer.py -f <*.eml/*.msg> -y <file/directory>
```

You can find one example under the ```yara_rules``` folder
```
python3 deMailer.py -f <*.eml/*.msg> -y yara_rules/image.yar
```

---

## Display modes

> The output can be sometimes overwelming or in some scenarios you might be interested in receiving screen output from certain components. To enable this, you have to use ```-m/--mode``` flag with your number(s) of preference.

**Note**: This is a display option and doesn't disable the functionalities of the tool. That means, any of your display option will not affect its performance but only what is printed to the end-user.  

```
Print to screen your specified mode (Default:0), 
[0]=All,[1]=Routing table,[2]=Footprints,[3]=Email addresses,[4]=URLs,[5]=GeoIP,[6]=DNS Lookup,[7]=WhoIs,[8]=Observables,[9]=Checks
```

```
python3 deMailer.py -f <*.eml/*.msg> -m 1
python3 deMailer.py -f <*.eml/*.msg> -m 3,8
```

---

## Output

> The results can be saved to a JSON file with ```-s/--saveJSON``` flag. Having the results in this format can be handy when you have an intelligence platform and you want to enrich it these data. The second option ```--table_format``` changes the table format in your screen output, which by default is the ```fancy_grid```. This flag is useful when you want to copy/paste the table output to a 3rd party app, for example: Jira.  In that case, instead using ```fancy_grid```, you'll need to change it to ```jira```.

```
python3 deMailer.py -f <*.eml/*.msg> -s results.json
```

```
python3 deMailer.py -f <*.eml/*.msg> --table_format jira
```

**More information about table formats can be found: https://pypi.org/project/tabulate/

---

## Exclude from scanning

> You know your environment better than anyone else and you can take further control over scanning by excluding IPs, Domains or Email addresses you believe are clean and their behavior is expected. The excluded atomics are visible in ```IsWhitelisted``` column within some tables and have the boolean value ```true```. These atomics are excluded from any type of request as well as from VT scans.

**Note:** In current version, deMailer is not collecting information about email addresses but in the futured version this functionality will be added. For this reason ```--exclude_emails``` flag is important.

### Excluding IP(s)

```
python3 deMailer.py -f <*.eml/*.msg> --exclude_ips 93.25.36.147,97.48.69.11
python3 deMailer.py -f <*.eml/*.msg> --exclude_ips 93.25.36.1/24
```

**Results**

```
...
╒═══════════════╤════════════════════════════════╤═════════╤═══════════╤════════════════════════════╤═════════════╤═════════════════╕
│ IP Address    │ DnsRecord                      │ Ccode   │ Country   │ Location                   │ IsPrivate   │ IsWhitelisted   │
╞═══════════════╪════════════════════════════════╪═════════╪═══════════╪════════════════════════════╪═════════════╪═════════════════╡
│ 93.25.36.147  │ -                              │ -       │ -         │ -,-                        │ False       │ True            │
├───────────────┼────────────────────────────────┼─────────┼───────────┼────────────────────────────┼─────────────┼─────────────────┤
├───────────────┼────────────────────────────────┼─────────┼───────────┼────────────────────────────┼─────────────┼─────────────────┤
│ 97.48.69.11   │ -                              │ -       │ -         │ -,-                        │ False       │ True            │
...
```

### Excluding Domain(s)

```
python3 deMailer.py -f <*.eml/*.msg> --exclude_domains gmail.com,microsoft.com
python3 deMailer.py -f <*.eml/*.msg> --exclude_domains www.google.com
```

Use the asterisk when you know are confident that email headers contain multiple subdomains or TLD from known resource:
```
python3 deMailer.py -f <*.eml/*.msg> --exclude_domains *google.com
python3 deMailer.py -f <*.eml/*.msg> --exclude_domains google*
```

Use the following string matcher for domains that contain multiple subdomains AND TLDs

```
python3 deMailer.py -f <*.eml/*.msg> --exclude_domains *google*
```
---

## Manual checks

> On this component, ```deMailer``` is performing various checks between headers. If value doesn't meet a requirement then the header check is flagged as ```Suspicious``` otherwise ```OK```. A single misconfiguration on the DKIM or SPF header can easily set the related checks as ```Suspicious``` and make you believe this is phishing email. Be mindful when you read the output and use other resources to validate the results. <b>Always look the problem holistically and not rely only to a sibgle header check<b>.

**Note**: Always pay extra attention to DKIM, SPF and DMARC checks

---

## Reporting

> Finally, you will receive a report in ```html``` format, which has a similar output with what you get on your screen. The report will be saved under ```/html_report/```. The attachments (if exists) will be extracted and saved under ```/attachments/``` folder. deMailer will strip the tags from the email ```body``` without text content or without properties and will save it the results with a ```.txt``` extension under ```/BODY2TXT/``` folder. This can enable you to distinct the most suspicious tags.


```
[+] Email attachments saved under: ['/home/deMailer/attachments/Message 167168370508.one']
[+] Email body converted to text and saved under: /home/deMailer/BODY2TXT/body2txt_stripped.txt
[+] Output saved to HTML file: /home/deMailer/html_report/2023-03-17-Emotet-E5-malspam-1644-UTC_report.html

```

--- 

## Credits

> The core of the deMailer is based on countless public phishing reports and . However, I would like to thank [malware-traffic-analysis](https://www.malware-traffic-analysis.net) for its malspam collection, which I relied on during the developing process. [JoshData](https://github.com/JoshData) for the amazing work that has done on the ```msg``` [converter](https://github.com/JoshData/convert-outlook-msg-file), which deMailer uses for converting ```msg``` to ```eml```. **A massive thank you to the best dev community - ```StackOverFlow```**

---

### References:

[1] https://wiki.archlinux.org/title/Xhost
