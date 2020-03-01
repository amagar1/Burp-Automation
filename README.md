# Burp Rest API scan Automation with ELK  
  
  
This is a simple script to run Burp Scans using Burp Rest API introduced in [Burp 2.x](https://portswigger.net/blog/burps-new-rest-api) and upload the scan results to an ELK once the scan is finished.   

ELK provides actionable Analytics for the vulnerability scans. ELK can also used Kibana to create visualisations for Burp scans.
   
## How to Use the Script:  
### Create an ELK Index:
 -  Create an Index for burp vulnerabilities.
	  ```console  
	 foo@bar:~$ curl -XPUT "http://elasticsearch:9200/burp-vulns" 
	 {"acknowledged":true,"shards_acknowledged":true,"index":"burp-vulns"}%    
	 ```  
 - Import Index Mapping using the template provided. 
	```console  
	foo@bar:~$  curl -H 'Content-Type: application/json' -XPUT 'http://elasticsearch:9200/burp-vulns/_mapping' -d @templates/burp_index_mapping.json
	```
###  Run Burp Script
 - Script Usage
 ```console  
foo@bar:~$  python Burp.py -h                                                                                                   
usage: Burp.py [-h] [-U USERNAME] [-P] URL

Burp scan Automation and reporting

positional arguments:
  URL                   Add URL of the Web Application

optional arguments:
  -h, --help            show this help message and exit
  -U USERNAME, --USERNAME USERNAME
                        Username for Authentication
  -P, --PASSWORD        Password
```  
 - Make sure that Burp Suite is running and Rest API is enabled.
 - Create a .env file with following parameters:
 

> BURP_URL=http://0.0.0.0:1337/v0.1/  
 ES_HOST=http://192.168.153.219:9200/  
 ES_USER='elastic'  
 ES_PASS='changeme'
 - Setup Python virtual environment
```console  
	 foo@bar:~$ python -m venv venv
	 foo@bar:~$ source venv/bin/activate
``` 
 - Execute Burp Script
 ```console  
foo@bar:~$  python Burp.py 'http://scanme.url/'                                                                          
	Burp scan initiated successfully!
	Burp Report uploaded  successfully to ELK
```
 - Once the scan is completed, login to Kibana and create index pattern with **date_found** as **Time Filter** field.

## Sample Kibana Dashboard:  
 ![Kibana Dashboard](https://i.imgur.com/y0GTDOs.png)

## TODO
- [ ] Add API Token Authentication for Burp API
- [ ] Add following Burp Scan API Options. (Scope, scan_configurations, application_logins)
- [ ] Add Notification Options(Email, Slack)
