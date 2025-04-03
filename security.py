import json
import os
import time
from datetime import datetime
from collections import defaultdict

def parse_timestamp(timestamp_str):
    return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

def load_blacklist():
    if os.path.exists('blacklist.txt'):
        with open('blacklist.txt', 'r') as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def add_to_blacklist(ip):
    blacklist = load_blacklist()
    if ip not in blacklist:
        with open('blacklist.txt', 'a') as f:
            f.write(f"{ip}\n")
        print(f"[ALERT] IP {ip} has been added to blacklist.txt")
        return True
    return False

def check_rate_limits(requests, threshold=20):
    # Group requests by second
    requests_by_second = defaultdict(list)
    for req in requests:
        timestamp = parse_timestamp(req['timestamp'])
        second_key = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        requests_by_second[second_key].append(req)
    
    # Check each second for violations
    violations = []
    for second, reqs in requests_by_second.items():
        if len(reqs) > threshold:
            violations.append({
                'timestamp': second,
                'count': len(reqs),
                'requests': reqs
            })
    return violations

def check_logs():
    for ip in os.listdir('logs'):
        ip_dir = os.path.join('logs', ip)
        if not os.path.isdir(ip_dir):
            continue
            
        client_info_file = os.path.join(ip_dir, 'client_info.json')
        if not os.path.exists(client_info_file):
            continue
            
        try:
            with open(client_info_file, "r") as f:
                # Read all lines and parse each JSON object
                requests = []
                for line in f:
                    try:
                        request_data = json.loads(line.strip())
                        requests.append(request_data)
                    except json.JSONDecodeError:
                        continue
                
                if not requests:
                    continue
                
                # Check GET requests
                get_requests = [req for req in requests if req['method'] == 'GET']
                get_violations = check_rate_limits(get_requests)
                
                # Check POST requests
                post_requests = [req for req in requests if req['method'] == 'POST']
                post_violations = check_rate_limits(post_requests)
                
                # Report violations and add to blacklist if needed
                if get_violations:
                    print(f"\n[WARNING] Rate limit violations detected for IP {ip} - GET requests:")
                    for violation in get_violations:
                        print(f"  - {violation['count']} GET requests at {violation['timestamp']}")
                    add_to_blacklist(ip)
                
                if post_violations:
                    print(f"\n[WARNING] Rate limit violations detected for IP {ip} - POST requests:")
                    for violation in post_violations:
                        print(f"  - {violation['count']} POST requests at {violation['timestamp']}")
                    add_to_blacklist(ip)
                
        except Exception as e:
            print(f"Error processing logs for IP {ip}: {str(e)}")

if __name__ == "__main__":
    if not os.path.exists('logs'):
        print("No logs found? Error exiting...")
        exit()
    while True:
        print("Checking logs...")
        print("-" * 50)
        print("Time: ", time.strftime("%Y-%m-%d %H:%M:%S"))
        check_logs()
        time.sleep(5)