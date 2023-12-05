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
