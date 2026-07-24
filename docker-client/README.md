# Reverse SSH Server for Synology, Linux and macOS

##This is a docker version of the remote-management-server client. 
##You can use this instead of the python which requires its own ec2. 

##installing the docker client 
git clone https://github.com/sigreen-nokia/remote-management-tsa.git
cd remote-management-tsa/docker-client

##Edit the path to point to the server public sh key
cat << "EOF" > .env
# Public-facing Synology ports.
SERVER_SSH_PORT=9000
REMOTE_SSH_PORT=9001
REMOTE_UI_PORT=9002
## SSH account used by the EC2 client.
OPS_USER=ops
## Absolute path on the Synology NAS to the EC2 client's PUBLIC key.
## This is not the private key.
CLIENT_PUBLIC_KEY_PATH=/var/services/homes/admin/remote-management-tsa/docker-client/id_rsa.pub
EOF

## Build and start the container
sudo docker-compose down --remove-orphans
sudo docker-compose build --no-cache
sudo docker-compose up -d

## Check status
sudo docker-compose ps
sudo docker-compose logs -f reverse-ssh-client

##After the EC2 tunnel connects, listeners should appear on ports `9001` and `9002`.
sudo docker exec reverse-ssh-client ss -lntp

## Testing locally on the docket host
ssh -v -p 9001 support@127.0.0.1
curl -k https://127.0.0.1:9002/

##testing remotely using the public ip or fqdn
curl -k https://[fqdn or ip]:9002
ssh -p 9001 support@[fqdn or ip]


