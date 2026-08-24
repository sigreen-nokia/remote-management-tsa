# Deepfield Remote Management Docker Client — Multi-Lab

This is the Docker replacement for the Python-based remote-management client host.
It can support **1 to 10 independent labs**, with one container per lab.

As a docker it's light, easy to deploy/remove and I'd expect it to run on most laptops, servers etc.

At the time of writing I've tested this docker successfully on my Synology nas and my macOS laptop.

One important point of note is that the docker client does not include all of the security measures of the python installer. It relies on the network to secure its access. So the docker is intended for use only in lab environments with a more relaxed security model. 

The python installer which deploys into its own operating system and environment and secures the Operating System specifically for TSA. It is intended for TSA secured production environments.  

## Design

Each lab gets a dedicated container and a dedicated three-port block:

| Lab | Client connection | Reverse SSH | Reverse HTTPS |
|---:|---:|---:|---:|
| 1 | 9000 | 9001 | 9002 |
| 2 | 9003 | 9004 | 9005 |
| 3 | 9006 | 9007 | 9008 |
| 4 | 9009 | 9010 | 9011 |
| 5 | 9012 | 9013 | 9014 |
| 6 | 9015 | 9016 | 9017 |
| 7 | 9018 | 9019 | 9020 |
| 8 | 9021 | 9022 | 9023 |
| 9 | 9024 | 9025 | 9026 |
| 10 | 9027 | 9028 | 9029 |

For example, Lab 2's Python server uses `CLIENT_SSH_TUNNEL_PORT=9003`.
It connects to Docker host port 9003 and requests reverse forwards on 9004 and 9005.

Each container has:
- its own sshd
- the same shared `authorized_keys` file containing all configured lab public keys
- its own persistent SSH host keys
- its own logs
- its own health state
- its own restart lifecycle

All containers share the same Docker image layers.

###Python based server install, install on the server you wish to connect to
```
git clone https://github.com/sigreen-nokia/remote-management-tsa.git
cd remote-management-tsa
sudo python3 mgmt-access.py --install-server
      9000      #lab2 9003 #lab3 9006 #lab4 9009 etc.
      [fqdn of the docker client]
      y
      y
sudo python3 mgmt-access.py --add-ops-user
sudo python3 mgmt-access.py --on --timer-override 0
```

###Docker based client install.

Run:

```bash
./setup.sh
```

Choose between 1 and 10 labs. Then enter each lab server **public-key file**
that should be trusted. Press ENTER when all keys have been entered.

`setup.sh` combines the supplied keys into a local `authorized_keys` file,
removes duplicate identical lines, and mounts that same file read-only into
every lab container. This intentionally allows any configured lab key to
authenticate to any lab container.

`setup.sh` generates:
- `.env`
- `docker-compose.yaml`
- `authorized_keys` — combined, de-duplicated public keys trusted by every lab container
- `LABS.txt` — the persistent lab/port/key map and usage instructions

Existing generated files are backed up first.

## Build and start

Synology / legacy Compose:

```bash
sudo docker-compose down --remove-orphans
sudo docker-compose build --no-cache
sudo docker-compose up -d
sudo docker-compose ps
```

Docker Compose v2:

```bash
sudo docker compose down --remove-orphans
sudo docker compose build --no-cache
sudo docker compose up -d
sudo docker compose ps
```

## Logs

Lab 1:

```bash
sudo docker-compose logs -f lab1
```

Lab 3:

```bash
sudo docker-compose logs -f lab3
```

## Check listeners

```bash
sudo docker exec reverse-ssh-client-lab1 ss -lntp
```

For Lab 1, after its Python server connects, expect ports 9000, 9001 and 9002.

For Lab 2:

```bash
sudo docker exec reverse-ssh-client-lab2 ss -lntp
```

Expect container listeners on 9000, 9004 and 9005. Host port 9003 maps to that container's port 9000.

## Python server configuration

No code changes are needed.

Use these `CLIENT_SSH_TUNNEL_PORT` values:

```text
Lab 1  = 9000
Lab 2  = 9003
Lab 3  = 9006
Lab 4  = 9009
Lab 5  = 9012
Lab 6  = 9015
Lab 7  = 9018
Lab 8  = 9021
Lab 9  = 9024
Lab 10 = 9027
```

The existing Python server automatically derives its SSH and UI forwards as +1 and +2.

## Testing

Lab 1:

```bash
ssh -p 9001 support@127.0.0.1
curl -k https://127.0.0.1:9002/
```

Lab 2:

```bash
ssh -p 9004 support@127.0.0.1
curl -k https://127.0.0.1:9005/
```

## Network security

For each active lab:
- the first port in the block is the inbound SSH control connection from that lab server
- the second port is remote SSH access to that lab
- the third port is remote HTTPS access to that lab

Restrict these at the Docker host/router/firewall according to your management network design.
