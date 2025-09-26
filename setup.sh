#!/bin/bash

# Firewall Bypass Toolkit - Setup Script
echo "[*] Setting up Firewall Bypass Toolkit..."


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' 


print_status() {
    echo -e "${CYAN}[+]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check Python version
print_status "Checking Python version..."
python3 --version >/dev/null 2>&1
if [ $? -ne 0 ]; then
    print_error "Python3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
print_success "Python $PYTHON_VERSION detected"

# Check pip
print_status "Checking pip installation..."
python3 -m pip --version >/dev/null 2>&1
if [ $? -ne 0 ]; then
    print_warning "pip not found. Installing pip..."
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python3 get-pip.py
    rm get-pip.py
fi

# Upgrade pip
print_status "Upgrading pip..."
python3 -m pip install --upgrade pip

# Create virtual environment
print_status "Creating virtual environment..."
python3 -m venv firewall_env

# Activate virtual environment
print_status "Activating virtual environment..."
source firewall_env/bin/activate

# Install requirements
print_status "Installing Python packages..."
pip install -r requirements.txt



# Create necessary directories
print_status "Creating workspace directories..."
mkdir -p logs
mkdir -p results
mkdir -p wordlists
mkdir -p config

# Create default configuration file
print_status "Creating default configuration..."
cat > config/default.yaml << EOF
# Firewall Bypass Toolkit Configuration

settings:
  timeout: 10
  max_retries: 3
  threads: 50
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

firewall_detection:
  enable_ip_check: true
  enable_header_check: true
  enable_advanced_detection: true

bruteforce:
  enable_subdomain_bruteforce: true
  enable_directory_bruteforce: false
  wordlist_size: medium

output:
  colors: true
  verbose: true
  save_results: true
EOF

# Create basic wordlists
print_status "Creating basic wordlists..."

# Subdomain wordlist
cat > wordlists/subdomains.txt << EOF
api
admin
cpanel
backend
dev
staging
test
cdn
assets
static
app
mobile
mail
ftp
webmail
blog
www
secure
portal
vpn
EOF

# Headers wordlist for bypass
cat > wordlists/headers.txt << EOF
X-Bypass-Firewall
X-Whitehat-Scan
X-Health-Check
X-Pentest-Approved
X-API-Version
X-Mobile-Gateway
X-Forwarded-For
X-Real-IP
X-Originating-IP
X-Client-IP
X-HTTP-Method-Override
X-CSRF-Token
X-Requested-With
X-Ajax-Navigation
EOF

# Test installation
print_status "Testing installation..."
python3 -c "
try:
    import requests, dns.resolver, colorama, netaddr
    print('✓ All required packages imported successfully')
except ImportError as e:
    print(f'✗ Missing package: {e}')
"

if [ $? -eq 0 ]; then
    print_success "Installation completed successfully!"
    echo ""
    echo -e "${GREEN}Firewall Bypass Toolkit is ready!${NC}"
    echo ""
    echo -e "${YELLOW}To start using the toolkit:${NC}"
    echo -e "  ${CYAN}python3 evilwaf.py --help${NC}"
    echo ""
    echo -e "${GREEN}Available features:${NC}"
    echo -e "  ${GREEN}• Firewall detection (100+ firewalls)${NC}"
    echo -e "  ${GREEN}• Header manipulation & bypass${NC}"
    echo -e "  ${GREEN}• Subdomain enumeration${NC}"
    echo -e "  ${GREEN}• DNS reconnaissance${NC}"
    echo -e "  ${GREEN}• Colored output${NC}"
else
    print_error "Installation test failed. Please check the errors above."
    exit 1
fi
