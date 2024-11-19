import socket
import struct
import textwrap

def main():
    # Create a raw socket that listens to Ethernet frames for IPv4 (protocol 0x0800)
    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0800))

    while True:
        # Receive raw Ethernet frame (max size is 65536 bytes)
        raw_data, address = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        print('\nETHERNET FRAME: ')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

# Unpack the Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(src_mac), get_mac_addr(dest_mac), socket.htons(proto), data[14:]

# Return a properly formatted MAC address
def get_mac_addr(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()

# unpacks ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length  >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, src, target, ipv4(src), ipv4(target), data[ header_length:]

# properly formatted ipv4 addr
def ipv4(addr):

    return '.'.join(map(str, addr))

# unpacks ICMP packet   
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return  icmp_type, code, checksum, data [4:]

#  unpacks TCP segment   
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowlegment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowlegment, offset_reserved_flags, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]   

# unpack the UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2X H', data[:8])
    return  src_port, dest_port, size, data[8:]

# formatt multi line data

def format_multi_line(prefix, string, size):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join( '\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])




# Run the main function
main()
