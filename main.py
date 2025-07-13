#!/usr/bin/env python3.11
import mcp
from os import getenv
import platform
import re
import subprocess
from mcp.server.fastmcp import FastMCP
from fabric import Connection, Result
from typing import List, Optional

# Create a FastMCP instance
fast_mcp = FastMCP("Linux-MCP")
DEBUG_MODE = False

# Check if a host responds thru an SSH connection
def responds(user: str = "e", host: str = "localhost") -> str:
    """
    Tests if a host is alive using SSH
    Args:
        user (str): The username for SSH authentication.
        host (str): The host to SSH connection.
    Returns:
        SUCCESS on valid ssh response, or FAILURE otherwise.
    """
    COMMAND = "exit 0"
    TIMEOUT = 10
    AUTH_TIMEOUT = 5
    try:
        res = Connection(host, user=user,
            connect_kwargs = {
        "timeout":TIMEOUT,
        "auth_timeout":AUTH_TIMEOUT}).run(COMMAND, hide=True)
        response = "SUCCESS"
    except Exception as e:
        response = "FAILURE"
    return response

fast_mcp.add_tool(responds)

# Asks what name a host recognizes itself
def hostname(user: str = "e", host: str = "localhost") -> str:
    """
    Asks a host what is its name
    Args:
        user (str): The username for SSH authentication.
        host (str): The host to SSH connection.
    Returns:
        hostname on valid ping response, or None otherwise.
    """
    COMMAND = "hostname"
    TIMEOUT = 10
    AUTH_TIMEOUT = 5
    try:
        res = Connection(host, user=user,
            connect_kwargs = {
        "timeout":TIMEOUT,
        "auth_timeout":AUTH_TIMEOUT}).run(COMMAND, hide=True)
        response = res.stdout.strip()
    except Exception as e:
        response = None
    return response

fast_mcp.add_tool(hostname)

# Asks what address a host have
def address(user: str = "e", host: str = "localhost", command: str = "ifconfig -a") -> List[str]:
    """
    Asks a host what addresses it have

    Args:
        user (str): The username to connect with.
        host (str): The hostname or IP address of the remote machine.
        command (str): The command to get the IP address of the remote machine

    Returns:
        List[str]: A list of unique IP addresses found, excluding '127.0.0.1'.
                   Returns an empty list if no valid IPs are found or an error occurs.
    """
    ip_addresses = []
    try:
        if DEBUG_MODE:
            print(f"Attempting to connect to {user}@{host}...")
        with Connection(host, user=user) as c:
            result: Result = c.run(command, hide=True)
            print(f"{result=}")
            if result.ok:
                output = result.stdout
                # print("Command executed successfully. Parsing output...")
                # Regular expression to find IPv4 addresses
                ip_pattern = re.compile(r'inet\s*(?:addr:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

                found_ips = ip_pattern.findall(output)

                # Filter out the loopback address and ensure uniqueness
                for ip in found_ips:
                    if ip != '127.0.0.1' and ip not in ip_addresses:
                        ip_addresses.append(ip)
                if DEBUG_MODE:
                  print(f"Found IP addresses: {ip_addresses}")
            else:
                if DEBUG_MODE:
                    print(f"Error running '{command}': {result.stderr}")

    except Exception as e:
        print(f"An error occurred: {e}")
    return sorted(ip_addresses)

fast_mcp.add_tool(address)

# Checks if a host is alive using ping
def alive(host: str, count: int = 1, timeout: int = 1) -> str:
    """
    Checks if a host is alive using ping

    Args:
        host (str): The hostname or IP address to ping.
        count (int): Number of ping packets to send.
        timeout (int): Timeout in seconds for each ping.

    Returns:
        str: SUCCESS if the host is reachable (at least one ping successful), FAILURE otherwise.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'

    command = ['ping', param, str(count), timeout_param, str(timeout), host]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            if platform.system().lower() == 'windows':
                if "Received = 1" in result.stdout and "Lost = 0" in result.stdout:
                    return "SUCCESS"
            else: # Linux/macOS
                match = re.search(r'(\d+) packets transmitted, (\d+) received', result.stdout)
                if match:
                    transmitted = int(match.group(1))
                    received = int(match.group(2))
                    if received > 0:
                        return "SUCCESS"
                else: # Fallback for different output formats
                    if "0% packet loss" in result.stdout:
                        return "SUCCESS"
        elif result.returncode == 2 and platform.system().lower() != 'windows':
            if "unknown host" in result.stderr.lower() or "destination host unreachable" in result.stderr.lower():
                return "FAILURE"
            match = re.search(r'(\d+) packets transmitted, (\d+) received', result.stdout)
            if match and int(match.group(2)) > 0:
                return "SUCCESS"

        return False # No successful ping detected
    except FileNotFoundError:
        if DEBUG_MODE:
          print(f"Error: 'ping' command not found. Please ensure it's in your system's PATH.")
        return "FAILURE"
    except Exception as e:
        if DEBUG_MODE:
          print(f"An unexpected error occurred while pinging {host}: {e}")
        return "FAILURE"

fast_mcp.add_tool(alive)

# Asks what users a host have
def users(user: str = "e", host: str = "localhost", command: str = "cat /etc/passwd", system: bool = False) -> List[str]:
    """
    Asks a host what users does it have

    Args:
        user (str): The username to connect with.
        host (str): The hostname or IP address of the remote machine.
        command (str): The command to get the IP address of the remote machine
        system (bool): If to include system users in the list

    Returns:
        List[str]: A list of users excluding root
                   Returns an empty list if no valid users are found or an error occurs.
    """
    user_list: List(str) = []
    SYSTEM_USER: int = 1000
    try:
        if DEBUG_MODE:
            print(f"Attempting to connect to {user}@{host}...")
        with Connection(host, user=user) as c:
            result: Result = c.run(command, hide=True)
            print(f"{result=}")
            if result.ok:
                output = result.stdout
                # if DEBUG_MODE:
                #     print(f"{output=}")
                # print("Command executed successfully. Parsing output...")
                # Regular expression to find IPv4 addresses
                user_pattern = re.compile(r'^([a-z][A-Za-z]*):(?:x)?:([0-9]{1,})?:')
                for output_line in output.split('\n'):
                    # if DEBUG_MODE:
                    #     print(f"{output_line=}")
                    found_user = user_pattern.findall(output_line)
                    if len(found_user)>0:
                        found_user = found_user[0]
                        the_username = found_user[0]
                        try:
                          the_userid = int(found_user[1])
                        except ValueError:
                          the_userid = -1
                        if DEBUG_MODE:
                            print(f"{the_username=} {the_userid=}")
                        if system or ((not system) and (the_userid>=SYSTEM_USER)):
                            if (the_username != 'root') and (the_username not in user_list):
                                user_list.append(the_username)
                if DEBUG_MODE:
                    print(f"Found users: {user_list}")
            else:
                if DEBUG_MODE:
                    print(f"Error running '{command}': {result.stderr}")

    except Exception as e:
        if DEBUG_MODE:
          print(f"An error occurred: {e}")
    return sorted(user_list)

fast_mcp.add_tool(users)

# Asks what filesystems a host have
def filesystems(user: str = "e", host: str = "localhost", command: str = "df -h", local: bool = False) -> List[str]:
    """
    Asks a host what filesystems does it have

    Args:
        user (str): The username to connect with.
        host (str): The hostname or IP address of the remote machine.
        command (str): The command to get the IP address of the remote machine
        local (bool): If to include system users in the list

    Returns:
        List[str]: A list of filesystems, may be only local or everything if local is False
                   Returns an empty list if no valid filesystems are found or an error occurs.
    """
    fs_list: List(str) = []
    try:
        if DEBUG_MODE:
            print(f"Attempting to connect to {user}@{host}...")
        with Connection(host, user=user) as c:
            result: Result = c.run(command, hide=True)
            print(f"{result=}")
            if result.ok:
                output_lines = result.stdout.strip().split("\n")
                # if DEBUG_MODE:
                #     print(f"{output=}")
                # print("Command executed successfully. Parsing output...")
                # Regular expression to find filesystems starting with
                #       /dev/ (block devices)
                #       //hostname/ (samba client filesystems)
                #       hostname:/  (nfs client filesystems)
                if len(output_lines)<2:
                    return []
                if local:
                    if DEBUG_MODE:
                        print("Local filesystems only")
                    fs_pattern = re.compile(r'^(?:/dev/).*?\s+([^\s]+)$')
                else:
                    fs_pattern = re.compile(r'^(?:/dev/|//[\w.-]+/|[\w.-]+:/).*?\s+([^\s]+)$')
                fs_list = []
                for output_line in output_lines:
                    if DEBUG_MODE:
                        print(f"{output_line=}")
                    match = fs_pattern.search(output_line)
                    if match:
                        fs_list.append(match.group(1))
                if not fs_list:
                    if DEBUG_MODE:
                        print("No filesystems found.")
                    return []
        if DEBUG_MODE:
            print(f"%s: {fs_list=}"%("Local filesystems only" if local else "All filesystems"))
        return fs_list
    except Exception as e:
        if DEBUG_MODE:
          print(f"An error occurred: {e}")
    return sorted(fs_list)

fast_mcp.add_tool(filesystems)

# Add a dynamic greeting resource
@fast_mcp.resource("greeting://{name}")
def greeting(name: str) -> str:
    """
    Generate a greeting message.
    Args:
        name (str): The name of the person to greet.
    Returns:
        str: The greeting message.
    """
    return f"Hello, {name}!"

# fast_mcp.add_resource("greeting", greeting)

# To make the server runnable, you need to add the mcp.run() call.
# This part was missing from your original snippet.
if __name__ == "__main__":
    if (getenv("DEBUG")=="True") or (getenv("DEBUG")=="true"):
        DEBUG_MODE = True
        print(f"{filesystems('e', 'scruffy', local=False)}")
    else:
      print("Starting Linux-MCP server...")
      fast_mcp.run() # By default, this uses the "stdio" transport for local execution
      print("Linux-MCP server stopped.")
