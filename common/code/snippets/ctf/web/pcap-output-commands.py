import base64
import struct
import dpkt
import sys

# packet sequence numbers that we will keep track of
sseq = -1 
dseq = -1 

def decode_b32(s):
    s = s.upper()
    for i in range(10):
        try:
            return base64.b32decode(s)
        except:
            s += b'='
    raise ValueError('Invalid base32')

def parse(name):
    # split payload data at periods, remove the top 
    # level domain name, and decode the data
    data = decode_b32(b''.join(name.split('.')[:-2]))
    (conn_id, seq, ack) = struct.unpack('<HHH', data[:6])
    return (seq, data[6:])

def handle(val, port):
    global sseq, dseq
    (seq,data) = parse(val)

    # remove empty packets
    if len(data) == 0:
        return

    #remove duplicates
    if port == 53:
        if sseq < seq:
            sseq = seq
        else:
            return
    else:
        if dseq < seq:
            dseq = seq
        else:
            return
    sys.stdout.write(data)

# main execution loop - go through all DNS packets, 
# decode payloads and dump them to the screen
for ts, pkt in dpkt.pcap.Reader(open('dump.pcap','r')):
    eth = dpkt.ethernet.Ethernet(pkt)
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            
            dns = dpkt.dns.DNS(udp.data)

            # extract commands from CNAME records and 
            # output from queries
            if udp.sport == 53: 
                for rr in dns.an:
                    if rr.type == dpkt.dns.DNS_CNAME:
                        handle(rr.cname, udp.sport)
            else:
                if dns.opcode == dpkt.dns.DNS_QUERY:
                    handle(dns.qd[0].name, udp.sport)
