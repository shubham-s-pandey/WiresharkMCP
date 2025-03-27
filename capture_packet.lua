local my_protocol = Proto("mcp_wireshark", "MCP Wireshark Integration Protocol")
local f_packet_no = ProtoField.uint32("mcp_wireshark.packet_no", "Packet Number", base.DEC)
local f_timestamp = ProtoField.string("mcp_wireshark.timestamp", "Timestamp")
local f_source = ProtoField.string("mcp_wireshark.source", "Source Address")
local f_destination = ProtoField.string("mcp_wireshark.destination", "Destination Address")
local f_protocol_name = ProtoField.string("mcp_wireshark.protocol_name", "Protocol Name")
local f_length = ProtoField.uint32("mcp_wireshark.length", "Packet Length", base.DEC)
my_protocol.fields = { 
    f_packet_no, f_timestamp, f_source, 
    f_destination, f_protocol_name, f_length 
}
local CONFIG = {
    PACKET_FILE = "C:\\Users\\Wireshark\\Downloads\\mcp_packet_details.txt",
    INTERFACES_FILE = "C:\\Users\\Wireshark\\Downloads\\network_interfaces.txt",
    MAX_BUFFER_SIZE = 50,
    MAX_DISPLAY_PACKETS = 100
}
local packet_buffer = {}

local function list_all_interfaces()
    local interfaces = {}
    
    local ok, err
    
    ok, err = pcall(function()
        local handle = io.popen("tshark -D")
        if handle then
            for line in handle:lines() do
                table.insert(interfaces, line)
            end
            handle:close()
        end
    end)
    
    if #interfaces == 0 then
        local iface_names = {
            "Ethernet", "Wi-Fi", "Loopback", "Local Area Connection", 
            "Wireless Network Connection", "Ethernet 1", "Wi-Fi 1"
        }
        for _, name in ipairs(iface_names) do
            table.insert(interfaces, name)
        end
    end
    
    local file = io.open(CONFIG.INTERFACES_FILE, "w")
    if file then
        file:write(table.concat(interfaces, "\n"))
        file:close()
    end
    
    return table.concat(interfaces, "\n")
end

function my_protocol.dissector(tvbuf, pinfo, tree)
    if tvbuf:len() < 4 then return end

    local protocol_name = "Unknown"
    if pinfo.curr_proto then
        protocol_name = tostring(pinfo.curr_proto)
    elseif pinfo.layer_name then
        protocol_name = tostring(pinfo.layer_name)
    end

    local packet_details = {
        no = pinfo.number or 0,
        timestamp = tostring(pinfo.abs_ts or os.time()),
        source = tostring(pinfo.src or "N/A"),
        destination = tostring(pinfo.dst or "N/A"),
        protocol = protocol_name,
        length = tvbuf:len(),
        additional_info = "No additional info"
    }

    local formatted_packet = string.format(
        "Packet No: %d, Time: %s, Src: %s, Dst: %s, Proto: %s, Length: %d, Info: %s\n",
        packet_details.no, 
        packet_details.timestamp, 
        packet_details.source, 
        packet_details.destination, 
        packet_details.protocol, 
        packet_details.length,
        packet_details.additional_info
    )

    table.insert(packet_buffer, formatted_packet)

    if #packet_buffer >= CONFIG.MAX_BUFFER_SIZE then
        local file = io.open(CONFIG.PACKET_FILE, "a")
        if file then
            for _, packet in ipairs(packet_buffer) do
                file:write(packet)
            end
            file:close()
        end
        packet_buffer = {}
    end

    local subtree = tree:add(my_protocol, tvbuf())
    subtree:add(f_packet_no, packet_details.no)
    subtree:add(f_timestamp, packet_details.timestamp)
    subtree:add(f_source, packet_details.source)
    subtree:add(f_destination, packet_details.destination)
    subtree:add(f_protocol_name, packet_details.protocol)
    subtree:add(f_length, packet_details.length)
end

register_postdissector(my_protocol)

function mcp_list_interfaces()
    return list_all_interfaces()
end