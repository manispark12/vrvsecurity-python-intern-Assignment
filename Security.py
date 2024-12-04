import re
from collections import Counter
import logging


logging.basicConfig(filename="accesslog.txt", level=logging.INFO)

# Regex pattern to match log entry components
log_pattern = r'(?P<ip>[\d\.]+) - - \[.*\] "(?P<method>[A-Z]+) (?P<url>[^\s]+) HTTP/[0-9\.]+" (?P<status>\d+)'


# Function to count requests per IP address
def count_requests_per_ip(log_file_path):
    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_login_counter = Counter()

    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                print(f"Processing line: {line.strip()}")
                match = re.match(log_pattern, line)

                if match:
                    ip_address = match.group('ip')
                    url = match.group('url')
                    status = int(match.group('status'))

                    print(f"Matched IP: {ip_address}, URL: {url}, Status: {status}")

                    # Count requests per IP
                    ip_counter[ip_address] += 1

                    # Count most frequently accessed endpoint (URL)
                    endpoint_counter[url] += 1

                    # Detect failed login attempts (HTTP status 401)
                    if status == 401:
                        failed_login_counter[ip_address] += 1

        return ip_counter, endpoint_counter, failed_login_counter

    except FileNotFoundError:
        print(f"Error: The log file '{log_file_path}' was not found.")
        return None, None, None


# Function to display and save results to CSV
def display_and_save_results(ip_counter, endpoint_counter, failed_login_counter):
    # Displaying the Requests per IP
    print(f"\n{'IP Address':<20} {'Request Count'}")
    for ip, count in ip_counter.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    # Displaying the Most Frequently Accessed Endpoint
    most_accessed_endpoint = endpoint_counter.most_common(1)
    if most_accessed_endpoint:
        endpoint, count = most_accessed_endpoint[0]
        print(f"{endpoint} (Accessed {count} times)")

    print("\nSuspicious Activity Detected:")
    # Displaying Suspicious Activity (failed login attempts)
    print(f"{'IP Address':<20} {'Failed Login Count'}")
    for ip, count in failed_login_counter.items():
        if count > 10:  # Flagging IP addresses with more than 10 failed login attempts
            print(f"{ip:<20} {count}")

    # Saving the results to a CSV file
    with open('log_analysis_results.csv', 'w') as csv_file:
        csv_file.write("IP Address,Request Count\n")
        for ip, count in ip_counter.items():
            csv_file.write(f"{ip},{count}\n")

        csv_file.write("\nEndpoint,Access Count\n")
        for endpoint, count in endpoint_counter.items():
            csv_file.write(f"{endpoint},{count}\n")

        csv_file.write("\nIP Address,Failed Login Count\n")
        for ip, count in failed_login_counter.items():
            if count > 10:  # Only save suspicious IPs
                csv_file.write(f"{ip},{count}\n")


# Main function
def main():
    log_file_path = 'accesslog.txt'
    ip_counter, endpoint_counter, failed_login_counter = count_requests_per_ip(log_file_path)

    if ip_counter is None:
        print("No data processed, please check the log file.")
        return

    display_and_save_results(ip_counter, endpoint_counter, failed_login_counter)


if __name__ == "__main__":
    main()