
#from scapy.layers.tls.all import *
import scapy.all as scapy
import scapy_p0f
import hashlib
from typing import Tuple
import redis
import traceback

rdb = redis.from_url('redis://redis:6379')

def ja3_from_tls_client_hello (pkt) -> Tuple[str, str]:
        #https://github.com/an0ndev/requests-ja3/blob/606fe61aea9e2c68e8c36b3e1654d0d69707a8be/requests_ja3/monitor/monitor.py#L14
        tls_client_hello = pkt['TLS'].msg [0]
        
        field_delimiter = ','
        value_delimiter = '-'
        out_fields = []

        try:
            tls_client_hello.version
        except KeyError:
            print (f"Likely not a ClientHello: {type (tls_client_hello)}")
            raise

        # def print_field (field_name): print (f"{field_name} {tls_client_hello.fields [field_name]}")
        # for field in ("version", "ciphers", "ext"): print_field (field)
        grease_values = [(base << 8) | base for base in [0xA | (upper_bit << 4) for upper_bit in range (16)]]

        # SSL Version
        out_fields.append (str (tls_client_hello.version))

        # Cipher
        out_ciphers = []
        for cipher in tls_client_hello.ciphers:
            if cipher in grease_values: continue
            out_ciphers.append (str (cipher))
        out_fields.append (value_delimiter.join (out_ciphers))

        # SSL Extension
        out_extensions = []
        ec_extension = None
        ec_formats_extension = None

        server_names = None

        for extension in tls_client_hello.ext:
            if extension.name == "TLS Extension - Server Name":
                server_names = list (server_name.servername.decode () for server_name in extension.fields ['servernames'])
                #if self.server_name not in server_names: return
            extension_type = extension.type
            if extension_type in grease_values: continue
            # if extension_type == 0x15: continue # "Padding"
            if extension.name == "TLS Extension - Scapy Unknown":
                print (f"WARNING: unknown extension {extension.type}, not adding to signature")
                continue
            out_extensions.append (str (extension.type))
            if extension.type == 10: # "Supported Groups"
                ec_extension = extension
            elif extension.type == 11: # "EC Point Formats"
                ec_formats_extension = extension
        out_fields.append (value_delimiter.join (out_extensions))

        #if server_names is None and self.server_name is not None: return

        # Elliptic Curve
        if ec_extension is not None:
            out_groups = []
            for group in ec_extension.fields ["groups"]:
                if group in grease_values: continue
                out_groups.append (str (group))
            out_fields.append (value_delimiter.join (out_groups))
        else: out_fields.append ("")

        # Elliptic Curve Point Format
        if ec_formats_extension is not None:
            out_fields.append (value_delimiter.join (str (point_format) for point_format in ec_formats_extension.fields ["ecpl"]))
        else: out_fields.append ("")

        string_ja3 = field_delimiter.join (out_fields)
        md5_ja3 = hashlib.md5 (string_ja3.encode ()).hexdigest ()
        return (string_ja3, md5_ja3)

def handle_packet(pkt):
    try:
        print(pkt.summary())
        src_ip = pkt['IP'].src
        sport = pkt['TCP'].sport
        key_str = f'{src_ip}:{sport}'

        if pkt['TCP'].flags == 2: # SYN-only packet, can't be ClientHello
            p0f_result = scapy_p0f.p0f(pkt['IP'])
            # Redis keys expire after 2 minutes
            if not p0f_result:
                rdb.set(f'{key_str}_tcp', '', ex=120)
                rdb.set(f'{key_str}_tcp_result', '', ex=120)
            else:
                p0f_result = p0f_result[0] if p0f_result else None
                parsed_p0f_result = f"{p0f_result[1]}:{' '.join(p0f_result[2:])}".strip()
                rdb.set(f'{key_str}_tcp', str(scapy_p0f.p0fv3.packet2p0f(pkt['IP'])[0]), ex=120)
                rdb.set(f'{key_str}_tcp_result', parsed_p0f_result, ex=120)

            if pkt['TCP'].dport == 80:
                # No JA3 on HTTP requests
                rdb.set(f'{key_str}_ja3', '', ex=120)
                rdb.set(f'{key_str}_ja3_hash', '', ex=120)

        else:
            ja3, ja3_hash = ja3_from_tls_client_hello(pkt)
            rdb.set(f'{key_str}_ja3', ja3, ex=120)
            rdb.set(f'{key_str}_ja3_hash', ja3_hash, ex=120)
    except Exception as e:
        traceback.print_exc()
        # Error occurred, set expected keys to blank
        for suffix in ['_tcp', '_tcp_result', 'ja3', 'ja3_hash']:
            if rdb.get(f'{key_str}{suffix}') is None:
                rdb.set(f'{key_str}{suffix}', '', ex=120)


scapy.load_layer('tls')
scapy.conf.use_pcap=True # use libpcap
# https://www.baeldung.com/linux/tcpdump-capture-ssl-handshake
scapy.sniff(filter='(tcp dst port 80 or 443) and ((tcp[tcpflags]==tcp-syn) or ((tcp[((tcp[12] & 0xf0) >> 2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01)))',
            prn=lambda x: handle_packet(x))