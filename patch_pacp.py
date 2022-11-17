import sys
import struct

# Patch pcap file to change from raw to ubetooth link layer

if len(sys.argv) < 2:
    print("Missing argument : pcap file")
    sys.exit(-1)
else:
    pcap_file_name = sys.argv[1]
print("File : ", pcap_file_name)

f = open(pcap_file_name, "r+b")
f.seek(21)
f.write(b'\x01')
