import logging
import os
import json
import time
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

CONFIG = {
    'PACKET_FILE': r'C:\Users\Wireshark\Downloads\mcp_packet_details.txt',
    'INTERFACES_FILE': r'C:\Users\Wireshark\Downloads\network_interfaces.txt',
    'MAX_DISPLAY_PACKETS': 100,
}

mcp = FastMCP("wireshark_packet_analyzer")

def read_packet_summaries(num_packets=CONFIG['MAX_DISPLAY_PACKETS']):
    """
    Read recent packet summaries from the file
    """
    try:
        if not os.path.exists(CONFIG['PACKET_FILE']):
            return "No packet capture file found. Start capturing packets in Wireshark."
        
        file_stats = os.stat(CONFIG['PACKET_FILE'])
        
        if file_stats.st_size == 0:
            return "Packet capture file is empty. Start capturing packets in Wireshark."
        
        if time.time() - file_stats.st_mtime > 3600:
            return "Packet capture file is outdated. Start a new capture in Wireshark."
        
        with open(CONFIG['PACKET_FILE'], 'r') as file:
            lines = file.readlines()
            start_index = max(0, len(lines) - num_packets)
            return ''.join(lines[start_index:]) if lines else "No packets captured yet."
    
    except Exception as e:
        logger.error(f"Error reading packet file: {e}")
        return f"Error reading packet file: {e}"

def get_network_interfaces():
    """
    Retrieve available network interfaces
    """
    try:
        if os.path.exists(CONFIG['INTERFACES_FILE']):
            with open(CONFIG['INTERFACES_FILE'], 'r') as f:
                interfaces = f.read().strip().split('\n')
                return '\n'.join(interfaces)
        
        import subprocess
        
        result = subprocess.run(['wmic', 'nic', 'get', 'Name,NetConnectionStatus'], 
                                capture_output=True, 
                                text=True, 
                                shell=True)
        
        interfaces = []
        for line in result.stdout.split('\n')[1:]:
            if line.strip():
                interfaces.append(line.strip())
        
        return '\n'.join(interfaces)
    
    except Exception as e:
        logger.error(f"Error retrieving network interfaces: {e}")
        return f"Error retrieving network interfaces: {e}"

def get_interface_details(interface_name):
    """
    Get detailed information about a specific interface
    """
    try:
        import subprocess
        
        result = subprocess.run(
            ['wmic', 'nic', 'where', f'Name="{interface_name}"', 'get', '*'], 
            capture_output=True, 
            text=True, 
            shell=True
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        else:
            return f"No details found for interface: {interface_name}"
    
    except Exception as e:
        logger.error(f"Error retrieving interface details: {e}")
        return f"Error retrieving interface details: {e}"

@mcp.tool()
async def list_interfaces() -> str:
    """
    MCP tool to list network interfaces
    """
    logger.debug("Listing network interfaces")
    return get_network_interfaces()

@mcp.tool()
async def get_packet_summary() -> str:
    """
    MCP tool to retrieve packet summaries
    """
    logger.debug("Retrieving packet summaries")
    return read_packet_summaries()

@mcp.tool()
async def clear_packet_file() -> str:
    """
    MCP tool to clear the packet capture file
    """
    try:
        if os.path.exists(CONFIG['PACKET_FILE']):
            os.remove(CONFIG['PACKET_FILE'])
        return "Packet capture file cleared successfully."
    except Exception as e:
        logger.error(f"Error clearing packet file: {e}")
        return f"Error clearing packet file: {e}"

@mcp.tool()
async def get_interface_details_tool(interface_name: str) -> str:
    """
    MCP tool to get detailed information about a specific interface
    """
    logger.debug(f"Retrieving details for interface: {interface_name}")
    return get_interface_details(interface_name)

# Main execution
if __name__ == "__main__":
    try:
        logger.info("Starting MCP server for Wireshark packet analysis")
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"MCP server error: {e}")