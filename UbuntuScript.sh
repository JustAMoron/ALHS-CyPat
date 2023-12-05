#!/bin/bash

# Welcome message
echo "Welcome to CyberPatriot Linux Security Script"
echo "Initiating system check..."

# Check for available system updates
echo "Checking for system updates..."
sudo apt update

# Upgrade the system
echo "Upgrading system packages..."
sudo apt upgrade -y

# Install essential security tools
echo "Installing essential security tools..."
sudo apt install ufw -y
sudo apt install fail2ban -y
sudo apt install libpam-cracklib -y
sudo apt install bum -y

# Configure Firewall (UFW)
echo "Configuring firewall..."
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Enable Fail2ban
echo "Enabling Fail2ban..."
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check for and remove unnecessary packages
echo "Checking for unnecessary packages..."
sudo apt autoremove --purge -y

# Check for and install security patches
echo "Checking and installing security patches..."
sudo apt-get --only-upgrade install

# Check and secure user accounts
echo "Checking user accounts..."
echo "Ensure there are no unnecessary or insecure user accounts."
echo "Update passwords for all user accounts."
echo "Remove/disable unnecessary or unused accounts."

# Check file permissions
echo "Checking file permissions..."
echo "Ensure critical system files have appropriate permissions."
# Add specific commands to check file permissions here

# Check for unauthorized SUID/SGID files
echo "Checking for unauthorized SUID/SGID files..."
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; > suid_sgid_files.txt

# Review and update login banners
echo "Reviewing and updating login banners..."
# Add specific commands or instructions for updating login banners here

# Perform system logs review
echo "Performing system logs review..."
echo "Check system logs for any suspicious activities."
# Add specific commands or instructions for reviewing system logs here

# Disable guest account in LightDM
echo "Disabling guest account in LightDM..."
# Ensure LightDM is the display manager in use on your system
sudo sh -c 'echo "allow-guest=false" >> /etc/lightdm/lightdm.conf'

# Remove known hacking tools
echo "Removing known hacking tools..."
sudo apt-get purge -y john hydra nmap netcat

# Update SSH configuration to disable root login
echo "Disabling root login in SSH..."
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Harden SSH configuration
sudo sed -i '/Port/c\ Port 22' /etc/ssh/sshd_config
sudo sed -i '/Protocol/c\ Protocol 2' /etc/ssh/sshd_config
sudo sed -i '/HostKeyDSA/c\ HostKeyDSA SHA256:somethingverylongandunique' /etc/ssh/sshd_config
sudo -i '/RSA/c\ RSA SHA384:otherlongstring' /etc/ssh/sshd_config
sudo sed -i '/PubkeyAcceptedKeyTypes/c\ PubkeyAcceptedKeyTypes=~/.ssh/id_rsa' /etc/ssh/sshd_config

# Install libpam-cracklib
echo "Installing libpam-cracklib..."
sudo apt-get install libpam-cracklib -y

# Add password settings to /etc/login.defs
echo "Adjusting password aging settings in /etc/login.defs..."
sudo sed -i '/^PASS_MAX_DAYS/s/.*/PASS_MAX_DAYS 90/' /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/s/.*/PASS_MIN_DAYS 7/' /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/s/.*/PASS_WARN_AGE 14/' /etc/login.defs

# Add authentication rules to /etc/pam.d/common-auth
echo "Configuring authentication rules in /etc/pam.d/common-auth..."
sudo sh -c 'echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> /etc/pam.d/common-auth'

echo "Configuring sysctl settings..."
sudo sysctl -p
echo "
# Added for security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
" | sudo tee -a /etc/sysctl.conf

# 18. Check cronjobs
echo "Checking cronjobs..."
# Add specific commands to check cronjobs here

# 19. Check sudoers
echo "Checking sudoers file..."
# Add specific commands to check sudoers file here

# 20. Check the runlevels
echo "Checking runlevels..."
# Add specific commands to check runlevels here

# APACHE CONFIGURATION
# 1. Hide Apache Version number
echo "Hiding Apache Version number..."
echo "
# Hide Apache Version number
ServerSignature Off
ServerTokens Prod
" | sudo tee -a /etc/apache2/apache2.conf

# 2. Make sure Apache is running under its own user account and group
echo "Configuring Apache user and group..."
sudo adduser --system --no-create-home --disabled-login --disabled-password apache
sudo sed -i 's/User www-data/User apache/g' /etc/apache2/apache2.conf
sudo sed -i 's/Group www-data/Group apache/g' /etc/apache2/apache2.conf

# 3. Ensure that files outside the web root directory are not accessed
echo "Restricting access to files outside web root directory..."
echo "
<Directory />
    Order Deny,Allow
    Deny from all
    Options -Indexes
    AllowOverride None
</Directory>
<Directory /html>
    Order Allow,Deny
    Allow from all
</Directory>
" | sudo tee -a /etc/apache2/apache2.conf

# 4. Turn off directory browsing, Follow symbolic links, and CGI execution
echo "Turning off directory browsing, following symbolic links, and CGI execution..."
sudo sed -i '/<Directory \/html>/a Options None' /etc/apache2/apache2.conf

# 5. Install modsecurity
echo "Installing ModSecurity..."
sudo apt-get install libapache2-mod-security2 -y
sudo service apache2 restart

# 6. Lower the Timeout value in /etc/apache2/apache2.conf
echo "Lowering Timeout value in Apache..."
sudo sed -i 's/Timeout 300/Timeout 45/' /etc/apache2/apache2.conf

# MYSQL CONFIGURATION
# 1. Restrict remote MySQL access
echo "Restricting remote MySQL access..."
sudo sed -i '/bind-address/s/^#//g' /etc/mysql/my.cnf

# 2. Disable use of LOCAL INFILE
echo "Disabling use of LOCAL INFILE in MySQL..."
echo "
[mysqld]
local-infile=0
" | sudo tee -a /etc/mysql/my.cnf

# 3. Create Application Specific user
echo "Creating MySQL application-specific user..."
# Add specific commands to create MySQL user here

# 4. Improve Security with mysql_secure_installation
echo "Improving MySQL security with mysql_secure_installation..."
# Add specific commands for MySQL secure installation here

# PHP CONFIGURATION
# 1. Restrict PHP Information Leakage
echo "Restricting PHP Information Leakage..."
sudo sed -i 's/expose_php = On/expose_php = Off/' /etc/php5/apache2/php.ini

# 2. Disable Remote Code Execution
echo "Disabling Remote Code Execution in PHP..."
sudo sed -i '/allow_url_fopen/s/^/;/g' /etc/php5/apache2/php.ini
sudo sed -i '/allow_url_include/s/^/;/g' /etc/php5/apache2/php.ini

# 3. Disable dangerous PHP Functions
echo "Disabling dangerous PHP Functions..."
sudo sed -i 's/disable_functions = /disable_functions = exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec/' /etc/php5/apache2/php.ini

# 4. Enable Limits in PHP
echo "Enabling Limits in PHP..."
sudo sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 2M/' /etc/php5/apache2/php.ini
sudo sed -i 's/max_execution_time = 30/max_execution_time = 30/' /etc/php5/apache2/php.ini
sudo sed -i 's/max_input_time = 60/max_input_time = 60/' /etc/php5/apache2/php.ini

# Prompt to reboot the system
read -p "System check complete. Reboot required. Would you like to reboot now? (y/n): " choice
if [ "$choice" == "y" ]; then
    sudo reboot
else
    echo "Remember to reboot the system when convenient."
fi
