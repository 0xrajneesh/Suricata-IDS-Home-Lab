# Installing Suricata IDS on Ubuntu Server

1. Install Suricata on the Ubuntu endpoint. We tested this process with version 6.0.8 and it can take some time:
```
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata -y
```

2. Download and extract the Emerging Threats Suricata ruleset:
```
cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
sudo tar -xvzf emerging.rules.tar.gz && sudo mv rules/*.rules /etc/suricata/rules/
sudo chmod 640 /etc/suricata/rules/*.rules
```

3. Modify Suricata settings in the /etc/suricata/suricata.yaml file and set the following variables:
```JavaScript
HOME_NET: "<UBUNTU_IP>"
EXTERNAL_NET: "any"

default-rule-path: /etc/suricata/rules
rule-files:
- "*.rules"

# Global stats configuration
stats:
enabled: Yes

# Linux high speed capture support
af-packet:
  - interface: eth0
```

4. Restart the Suricata service:
```
sudo systemctl restart suricata
```



