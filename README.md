
## What is Remote management TSA:

![Alt text](images/process.png)


* A client server tool which provides MGMT access on demand, without using any inbound ports. 
* It is written in line with TSA regs, specifically Managagement Access Requirements. 
* The created ops user is locked down, only able to run mgmt-access.py 
* Everything is daemon based, so will survive restarts etc. 
* The tool runs on Ubuntu Linux 
* The install options are automated and will prompt you for the configuration values
* All values are configurable during the installation
* The default outbound port from the mgmt_server to the mgmt_client is 9000 tcp (no inbound ports are required)
* The default lan ports into the client, which are used for server access, are:
- 22 admin ssh access to the client 
- 9001 direct ssh access to the server on port 22 
- 9002 direct UI access to the server on port 443  

```
#help
python3 mgmt-access.py --help

#install the server (this is the on prem Linux server you want to access remotely)
pip install -r ./requirements.txt
python3 mgmt-access.py --install-server
python3 mgmt-access.py --add-ops-user  

#install the client instance: this is a minimal ubuntu 24.04 + ssh, one ip is enough. 
python3 mgmt-access.py --add-ops-user  
python3 mgmt-access.py --install-client

#start the remote mamagement service for 24 hours, usually ran by the ops user
python3 mgmt-access.py --on 

#start the remote management service for the specified number of hours 
python3 mgmt-access.py --on --timer-override 99 

#start the remote management service, run untill manually stopped with --off 
python3 mgmt-access.py --on --timer-override 0 

#stop the remote mamagement service, usually ran by the ops user
python3 mgmt-access.py --off

#remove the ops user
python3 mgmt-access.py --remove-ops-user

#status (the status output will change when it is ran on a server vs a client)
python3 mgmt-access.py --status

#detailed status 
python3 mgmt-access.py --status --log-level DEBUG

#uninstall the server
python3 mgmt-access.py --uninstall-client

#logs go to /var/log/syslog
```

