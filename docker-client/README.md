##This is a docker version of the remote-management-server client. 
##You can use this instead of the python which requires its own Ubuntu ec2. 
##As a docker it's light, easy to remove and I'd expect it to run on most laptops, servers etc. 
##At the time of writing I've tested this docker successfully on my Synology nas and my macOS laptop. 

###Server install on the server you wish to connect to
#The assumption is that you have already ran the python based server, on the secure device you wish to connect to.
#and that it is trying to connect to your docker host on port 9000
```
git clone https://github.com/sigreen-nokia/remote-management-tsa.git
cd remote-management-tsa
sudo python3 mgmt-access.py --install-server
      90000
      [fqdn of the docker client]
      y
      y
sudo python3 mgmt-access.py --add-ops-user
sudo python3 mgmt-access.py --on --timer-override 0
```

###install the docker client on the device you wish to use to connect to the server 
#Open up TCP port 9000 inbound, src ip is the secure device you ran the server on 
#use "docker compose" "or "docker-compose" whichever works
##installing the docker client 
```
git clone https://github.com/sigreen-nokia/remote-management-tsa.git
cd remote-management-tsa/docker-client
##Edit the path to point to the server public sh key
cat << "EOF" > .env
# Public-facing ports.
SERVER_SSH_PORT=9000
REMOTE_SSH_PORT=9001
REMOTE_UI_PORT=9002
## SSH account used by the EC2 client.
OPS_USER=ops
## Absolute path to the EC2 server PUBLIC key.
## This is not the private key.
CLIENT_PUBLIC_KEY_PATH=/var/services/homes/admin/remote-management-tsa/docker-client/id_rsa.pub
EOF
#
## Build and start the container
sudo docker-compose down --remove-orphans
sudo docker-compose build --no-cache
sudo docker-compose up -d
#
## Check status
sudo docker-compose ps
sudo docker-compose logs -f reverse-ssh-client
#
##After the EC2 tunnel connects, listeners should appear on ports `9001` and `9002`.
sudo docker exec reverse-ssh-client ss -lntp
#
## Testing locally on the docker host
ssh -v -p 9001 support@127.0.0.1
curl -k https://127.0.0.1:9002/
#
##testing remotely using the public ip or fqdn
#Open up TCP ports 9001 9002 inbound, src ip's are any subnets containing devices which need to connect
curl -k https://[fqdn or ip]:9002
ssh -p 9001 support@[fqdn or ip]
```

