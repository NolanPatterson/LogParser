import re
import csv
from datetime import datetime
import os

def parse_radius_detail_log(log_file_path, output_csv_path):
    """
    Parses a FreeRADIUS detail log file to extract authentication attempt info.
    
    Args:
        log_file_path (str): Path to the FreeRADIUS detail log file.
        output_csv_path (str): Path to save the parsed data as a CSV file.
    """
    parsed_data = []
    current_packet = None
    # Regex to match ctime header "Thu Jul 23 00:00:13 2015"
    # Adjust regex for custom header format in the freeradius detail module config
    timestamp_regex = re.compile(r"^\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}")
    # Regex used to match attribute-value pairs
    attribute_regex = re.compile(r"^\s*([\w-]+)\s*=\s*\"?(.*?)\"?\s*$")

    print(f"Attempting to parse log file: {log_file_path}")

    try:
        with open(log_file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                timestamp_match = timestamp_regex.match(line)
                if timestamp_match:
                    # Store the previously collected packet if valid
                    if current_packet:
                        # success/failure based on collected attributes
                        # might need adjustment depending on attributes
                        reply_msg = current_packet.get("Reply-Message", "").lower()
                        auth_type = current_packet.get("Auth-Type", "").lower() # Check the Auth-Type as well

                        if "login ok" in reply_msg or "access-accept" in reply_msg or "accept" in auth_type:
                            current_packet["status"] = "Success"
                        elif "login incorrect" in reply_msg or "access-reject" in reply_msg or "reject" in auth_type:
                            current_packet["status"] = "Failure"
                        else:
                            current_packet["status"] = "Unknown" # If a status can't be determined

                        # Ensure essential fields were found before adding
                        if "timestamp" in current_packet and "User-Name" in current_packet and "Calling-Station-Id" in current_packet:
                            parsed_data.append(current_packet)

                    # Start a new packet entry
                    try:
                        timestamp_dt = datetime.strptime(line, "%a %b %d %H:%M:%S %Y")
                        current_packet = {"timestamp": timestamp_dt.isoformat()}
                    except ValueError:
                        print(f"Warning: Could not parse timestamp format on line {line_num}: '{line}'. Skipping packet header.")
                        current_packet = None # if timestamp is unparseable
                        
                elif current_packet:
                    # If it's not a header and we have a valid current_packet, parse attribute
                    attribute_match = attribute_regex.match(line)
                    if attribute_match:
                        attr_name = attribute_match.group(1)
                        attr_value = attribute_match.group(2)
                        # Store attributes (add others if needed for feature engineering)
                        # a collection of attributes to check
                        valid_attributes = {"User-Name", "Calling-Station-Id", "Reply-Message",
                            "Auth-Type"}
                        if attr_name in valid_attributes:
                            current_packet[attr_name] = attr_value
                    # else:
                        # Optional: log lines that don't match the expected attribute format
                        # print(f"Warning: Could not parse attribute on line {line_num}: {line}")

                    # Process the very last packet after the loop finishes
                    if current_packet:
                        reply_msg = current_packet.get("Reply-Message", "").lower()
                        auth_type = current_packet.get("Auth-Type", "").lower()
                        if "login ok" in reply_msg or "access-accept" in reply_msg or "accept" in auth_type:
                            current_packet["status"] = "Success"
                        elif "login incorrect" in reply_msg or "access-reject" in reply_msg or "reject" in auth_type:
                            current_packet["status"] = "Failure"
                        else:
                            current_packet["status"] = "Unknown"
                        
                    if "timestamp" in current_packet and "User-Name" in current_packet and "Calling-Station-Id" in current_packet:
                        parsed_data.append(current_packet)
                    # uncomment below to see this warning
                    # else:
                        #print(f"Warning: Skipping last packet due to missing essential fields.
                        #Found: {current_packet.keys()}")
    
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return
    except Exception as e:
        print(f"An error occurred during parsing: {e}")
        return

    # Write parsed data to CSV
    if parsed_data:
        # Define headers
        all_keys = set().union(*(d.keys() for d in parsed_data))
        preferred_order = ["timestamp", "User-Name", "Calling-Station-Id", "Reply-Message", "Auth-Type", "status"]
        fieldnames = preferred_order + sorted([k for k in all_keys if k not in preferred_order])
        
        print(f"Parsing complete. Found {len(parsed_data)} valid log entries.")
        print(f"Writing data to: {output_csv_path}")
        
        try:
            with open(output_csv_path, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(parsed_data)
            print(f"Successfully saved parsed data to {output_csv_path}")
        except IOError as e:
            print(f"Error: Could not write to CSV file {output_csv_path}. Reason: {e}")
        except Exception as e:
            print(f"An error occurred while writing CSV: {e}")
    else:
        print("No valid log entries were parsed. Please check the log file format and content.")

log_directory = '/var/log/freeradius/' # log directory path
log_filename = 'auth_detail-2025-04-22' # CHANGE THIS for log file name
full_log_path = os.path.join(log_directory, log_filename)

# Path for output CSV file
output_csv_file = os.path.expanduser('~/Desktop/parsed_radius_auth_attempts.csv')

# Call the parsing function
parse_radius_detail_log(full_log_path, output_csv_file)
