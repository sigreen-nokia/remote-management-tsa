
## What is Remote management TSA:

* A client server tool which creates secured reverse SSH tunnels on demand, in line with TSA regs Managagement access requirements. 
* The tool runs on Ubuntu Linux 

```
pip install -r ./requirements.txt

#help
python3 remote-mgmt-tsa.py --help

#install the server (where the reverse ssh is started and stopped by ops)
python3 remote-mgmt-tsa.py --install-server
python3 remote-mgmt-tsa.py --add-ops-user  

#install the client instance: this is a minimal ubuntu 22.04 + ssh, one ip 
python3 remote-mgmt-tsa.py --install-client
python3 remote-mgmt-tsa.py --add-ops-user  

#start the remote mamagement service for 24 hours, usually ran by the ops user
python3 remote-mgmt-tsa.py --on 

#stop the remote mamagement service, usually ran by the ops user
python3 remote-mgmt-tsa.py --off

#start the remote management service for the specified number of hours 
python3 remote-mgmt-tsa.py --on --timer-override 99 

#remove the ops user
python3 remote-mgmt-tsa.py --remove-ops-user
```

