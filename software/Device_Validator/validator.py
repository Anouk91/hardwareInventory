from scapy.all import *
import binascii
import re
import requests


pcap=rdpcap("liaA-R.cap")
for packet in pcap:
    packet_sliced_src=packet[1].src.split(":")
    packet_hexal_lenght=len(packet_sliced_src)
    if(packet_hexal_lenght == 8):
        for i in range(packet_hexal_lenght):
            if(len(packet_sliced_src[i]) < 4):
                packet_sliced_src[i]="{}{}".format((4 - len(packet_sliced_src[i]))*"0", packet_sliced_src[i])
            else:
                pass
    else:
        shortening_index=packet_sliced_src.index("")
        for i in range(8 - packet_hexal_lenght):
            packet_sliced_src.insert(shortening_index + (i + 1), "0000")
        for i in range(8):
            if(len(packet_sliced_src[i]) < 4):
                packet_sliced_src[i]="{}{}".format((4 - len(packet_sliced_src[i]))*"0", packet_sliced_src[i])
            else:
                pass
    if (re.match("[^0*]", "".join(packet_sliced_src[4:]))):
        packet_to_mac= ("".join(packet_sliced_src[4:])).replace("fffe", "")
        packet_to_mac_bin=(int(packet_to_mac, 16))
        packet_mac=hex((packet_to_mac_bin) ^ (1<<41))[2:]
        mac_request= requests.get("http://api.macvendors.com/{}".format(packet_mac))
        print("{} - {}".format(packet_mac, mac_request.text))

        #print("Unflipped: {}\nFlipped:   {}".format(hex(int(packet_to_mac_bin, 2)), hex(int(str(int(packet_to_mac_bin) ^ int("000000100000000000000000000000000000000000000000")), 2))))
    else:
        pass
