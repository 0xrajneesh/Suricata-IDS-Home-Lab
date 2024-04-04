# Installing Suricata IDS on Ubuntu Server

1. Install Suricata on the Ubuntu endpoint. We tested this process with version 6.0.8 and it can take some time:
```
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata -y
```
