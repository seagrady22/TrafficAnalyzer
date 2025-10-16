#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
LOG_FILE="traffic_monitor.log"
ALERT_FILE="traffic_alerts.log"
ALERT_THRESHOLD_BYTES=10000000  # 10MB
SUSPICIOUS_COUNTRIES=("CN" "RU" "KP" "IR")  # Add more as needed
CHECK_INTERVAL=5  # seconds

# Function to send alert
send_alert() {
    local alert_type=$1
    local details=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local alert_message="[${timestamp}] ALERT: ${alert_type} - ${details}"
    
    # Log alert
    echo -e "${RED}${alert_message}${NC}" | tee -a $ALERT_FILE
    
    # You can add notification methods here:
    # - Email
    # - Desktop notification
    # - Sound alert
    # - etc.
}

# Function to get country from IP
get_country() {
    local ip=$1
    # Using ip-api.com (free service)
    country=$(curl -s "http://ip-api.com/json/$ip" | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4)
    echo $country
}

# Function to check suspicious IPs
check_suspicious_ips() {
    while true; do
        # Get established connections
        netstat -an | grep ESTABLISHED | while read line; do
            # Extract foreign IP
            foreign_ip=$(echo $line | awk '{print $5}' | cut -d: -f1)
            
            # Skip local and private IPs
            if [[ $foreign_ip == "127.0.0.1" ]] || [[ $foreign_ip == "::1" ]] || \
               [[ $foreign_ip =~ ^10\. ]] || [[ $foreign_ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
               [[ $foreign_ip =~ ^192\.168\. ]]; then
                continue
            fi
            
            # Get process info
            local_port=$(echo $line | awk '{print $4}' | cut -d: -f2)
            process_info=$(lsof -i :$local_port 2>/dev/null)
            
            if [ ! -z "$process_info" ]; then
                process_name=$(echo $process_info | awk '{print $1}')
                log_traffic "CONNECTION" "Process: $process_name, Foreign IP: $foreign_ip, Port: $local_port"
                
                # Check for suspicious countries
                country=$(get_country $foreign_ip)
                if [[ " ${SUSPICIOUS_COUNTRIES[@]} " =~ " ${country} " ]]; then
                    send_alert "SUSPICIOUS_COUNTRY" "Process: $process_name connecting to $country (IP: $foreign_ip)"
                fi
            fi
        done
        
        sleep $CHECK_INTERVAL
    done
}

# Function to monitor data transfer
monitor_data_transfer() {
    local last_bytes_in=0
    local last_bytes_out=0
    
    while true; do
        # Get network interface statistics
        netstat -ib | grep en0 | while read line; do
            bytes_in=$(echo $line | awk '{print $7}')
            bytes_out=$(echo $line | awk '{print $10}')
            
            # Calculate transfer since last check
            transfer_in=$((bytes_in - last_bytes_in))
            transfer_out=$((bytes_out - last_bytes_out))
            
            log_traffic "DATA_TRANSFER" "Bytes In: $bytes_in, Bytes Out: $bytes_out"
            
            # Check for unusual data transfer
            if [ $transfer_out -gt $ALERT_THRESHOLD_BYTES ]; then
                send_alert "HIGH_DATA_TRANSFER" "Unusual outbound data transfer: $transfer_out bytes"
            fi
            
            last_bytes_in=$bytes_in
            last_bytes_out=$bytes_out
        done
        
        sleep 60
    done
}

# Function to log traffic
log_traffic() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local type=$1
    local details=$2
    echo -e "[${timestamp}] ${type}: ${details}" | tee -a $LOG_FILE
}

# Main monitoring function
main() {
    echo "Starting traffic monitoring..."
    echo "Logging to: $LOG_FILE"
    echo "Alerts will be logged to: $ALERT_FILE"
    
    # Create alert file if it doesn't exist
    touch $ALERT_FILE
    
    # Start monitoring in background
    check_suspicious_ips &
    monitor_data_transfer &
    
    # Keep script running
    wait
}

# Run main function
main 