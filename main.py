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
                    print(f"Error running 'ifconfig -a': {result.stderr}")

    except Exception as e:
        print(f"An error occurred: {e}")
    return sorted(ip_addresses)

fast_mcp.add_tool(address)

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
        print(f"{alive('192.168.25.1')=}")
    else:
      print("Starting Linux-MCP server...")
      fast_mcp.run() # By default, this uses the "stdio" transport for local execution
      print("Linux-MCP server stopped.")
