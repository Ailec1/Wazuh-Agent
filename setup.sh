#!/bin/bash

while true; do
    OPTION=$(whiptail --title "Main Menu" --menu "Choose an option:" 20 70 13 \
                    "1" "Update System and Install Prerequisites Debian/Ubuntu" \
                    "2" "Install Wazuh Agent Debian/Ubuntu" \
                    "3" "Install Yara Debian/Ubuntu" \
                    "4" "Install Wazuh Agent Fedora" \
                    "5" "Install Yara Fedora"  3>&1 1>&2 2>&3)
    # Script version 1.0 updated 15 November 2023
    # Depending on the chosen option, execute the corresponding command
    case $OPTION in
    1)
        sudo apt-get update -y
        sudo apt-get upgrade -y
        sudo apt-get install wget curl nano git unzip -y
        # sudo apt-get install wget curl nano git unzip ca-certificates -y
        ;;
    2)
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
        sudo apt-get update -y
        WAZUH_MANAGER="10.0.70.2" apt-get install wazuh-agent
        systemctl daemon-reload
        systemctl enable wazuh-agent
        systemctl start wazuh-agent
        cp integration/remove-threat.sh /var/ossec/active-response/bin/remove-threat.sh
        sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
        sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh
        sudo systemctl restart wazuh-agent
        ;;
    3)
        sudo apt update
        sudo apt install -y make gcc autoconf libtool libssl-dev pkg-config jq
        sudo curl -LO https://github.com/VirusTotal/yara/archive/v4.2.3.tar.gz
        sudo tar -xvzf v4.2.3.tar.gz -C /usr/local/bin/ && rm -f v4.2.3.tar.gz
        cd /usr/local/bin/yara-4.2.3/
        sudo ./bootstrap.sh && sudo ./configure && sudo make && sudo make install && sudo make check
        sudo echo "/usr/local/lib" >> /etc/ld.so.conf
        sudo ldconfig
        sudo mkdir -p /tmp/yara/rules
        sudo curl 'https://valhalla.nextron-systems.com/api/v1/get' \
        -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
        -H 'Accept-Language: en-US,en;q=0.5' \
        --compressed \
        -H 'Referer: https://valhalla.nextron-systems.com/' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' \
        --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
        -o /tmp/yara/rules/yara_rules.yar
        cp integration/yara.sh /var/ossec/active-response/bin/yara.sh
        sudo chmod 750 /var/ossec/active-response/bin/yara.sh
        sudo chown root:wazuh /var/ossec/active-response/bin/yara.sh
        sudo systemctl restart wazuh-agent
        ;;
    4)
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat > /etc/yum.repos.d/wazuh.repo << EOF
        [wazuh]
        gpgcheck=1
        gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
        enabled=1
        name=EL-\$releasever - Wazuh
        baseurl=https://packages.wazuh.com/4.x/yum/
        protect=1
        EOF
        WAZUH_MANAGER="10.0.70.2" yum install wazuh-agent
        systemctl daemon-reload
        systemctl enable wazuh-agent
        systemctl start wazuh-agent
        ;;
    5)
        ;;
    
esac
    # Give option to go back to the previous menu or exit
    if (whiptail --title "Exit" --yesno "Do you want to exit the script?" 8 78); then
        break
    else
        continue
    fi
done
