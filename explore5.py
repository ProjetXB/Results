from pprint import pprint
from struct import pack
import database
import sqlalchemy
from sqlalchemy.sql import func, and_
import datetime
from scapy.all import *

def pydict_count(d, key):
    if not key in d:
        d[key] = 1
    else:
        d[key] += 1
    return d

def pydict_list(d, key, value):
    if not key in d:
        d[key] = [value]
    else:
        d[key].append(value)
    return d

def check_packet(packet):
    all_layers = packet.layers.split("/")
    first_layer = all_layers[0].strip()
    last_layer = all_layers[-1].strip()
    if first_layer == "PPI":
        scapy_packet = PPI(bytes.fromhex(packet.raw))
    elif first_layer == "BTLE_RF":
        scapy_packet = BTLE_RF(bytes.fromhex(packet.raw))
    else:
        raise Exception("Packet layer un known %s" % first_layer)
    if scapy_packet.haslayer(EIR_CompleteLocalName):
        return "Named device : %s" % scapy_packet[EIR_CompleteLocalName].local_name
    if scapy_packet.haslayer(EIR_Manufacturer_Specific_Data):
        if scapy_packet[EIR_Manufacturer_Specific_Data].company_id == 76:
            return "Apple device"
        elif scapy_packet[EIR_Manufacturer_Specific_Data].company_id == 6:
            return "Microsoft device"
        elif scapy_packet[EIR_Manufacturer_Specific_Data].company_id == 0x87:
            return "Garmin device"
        elif scapy_packet[EIR_Manufacturer_Specific_Data].company_id == 0x110:
            return "Nippon Seiki Co., Ltd."
        elif scapy_packet[EIR_Manufacturer_Specific_Data].company_id == 0x8AA:
            return "SZ DJI TECHNOLOGY CO.,LTD"
        else:
            return "??? Device manufacurer 0x%X" % scapy_packet[EIR_Manufacturer_Specific_Data].company_id
    if packet.pdu_type in [0, 1, 2]:
        data = None
        if scapy_packet.haslayer(BTLE_ADV_IND):
            data = scapy_packet[BTLE_ADV_IND].data
        elif scapy_packet.haslayer(BTLE_ADV_NONCONN_IND):
            data = scapy_packet[BTLE_ADV_NONCONN_IND].data
        elif scapy_packet.haslayer(BTLE_ADV_DIRECT_IND):
            data = scapy_packet[BTLE_ADV_DIRECT_IND].data
        if data is not None:
            eir_list = []
            for hrd in data:
                eir_list.append(hrd.mysummary())
            eir_trace = "+".join(eir_list)                   
            if scapy_packet.haslayer(EIR_CompleteList16BitServiceUUIDs):
                uuid_16 = scapy_packet[EIR_CompleteList16BitServiceUUIDs].svc_uuids[0]
                if uuid_16 == 0xfd64:
                    return "TousAntiCovid 0xfd64"
                elif uuid_16 == 0xfd6f:
                    return "TousAntiCovid 0xfd6f"
                elif uuid_16 == 0x1800:
                    eir_trace += " Generic access profile !"
                elif uuid_16 == 0x180a:
                    eir_trace += " Device information !"
            if scapy_packet.haslayer(EIR_CompleteList128BitServiceUUIDs):
                uuid_128 = str(scapy_packet[EIR_CompleteList128BitServiceUUIDs].svc_uuids[0])
                if uuid_128 == "291d567a-6d75-11e6-8b77-86f30ca893d3":
                    return "Blackmagic Camera"
                elif uuid_128 == "0000fd64-0000-1000-8000-00805f9b34fb":
                    return "TousAntiCovid 0xfd64"
            if scapy_packet.haslayer(EIR_IncompleteList128BitServiceUUIDs):
                uuid_128 = str(scapy_packet[EIR_IncompleteList128BitServiceUUIDs].svc_uuids[0])
                if uuid_128 == "adabfb00-6e7d-4601-bda2-bffaa68956ba":
                    return "Fitbit Charge HR fitness trackers"
                elif uuid_128 == 'abbaff00-e56a-484c-b832-8b17cf6cbfe8':
                    return "Montre Vera Lite"

            return "??? %s %s" %(last_layer, eir_trace)
    elif packet.pdu_type == 3: # SCAN_REQ
        return "SCAN_REQ"
    elif packet.pdu_type == 4: # SCAN_RSP
        return "SCAN_RSP"
    return "??? %s PDU_TYPE %d" % (last_layer, packet.pdu_type)

nb_packet_total = database.session.query(database.Packet).count()
print("Number of paquets : ", nb_packet_total)
# Analyse des paquets à CRC OK
packets = database.session.query(database.Packet).filter_by(crc=1).all()
print("Number of packet with valid CRC :", len(packets))
# Count macs
macs = {}
for packet in packets:
    if not packet.mac in macs:
        macs[packet.mac] = [packet]
    else:
        macs[packet.mac].append(packet)

sorted_mac = sorted(macs.items(), key=lambda x: len(x[1]), reverse=True)

if None in macs:
    none_mac_pdu_types = {}
    for packet in macs[None]:
        pydict_list(none_mac_pdu_types, packet.pdu_type, packet)

    print("Number of packet with no MAC", len(macs[None]))
    print("None MAC PDU_TYPE repatition :")
    print("")

    for pdu_type in none_mac_pdu_types:
        print("PDU_TYPE", pdu_type)
        file_list = {}
        for packet in none_mac_pdu_types[pdu_type]:
            pydict_count(file_list, packet.pcap_file)
        sorted_file_list = sorted(file_list.items(), key=lambda x: x[1], reverse=True)
        for files, nb in sorted_file_list:
            print(files, nb)
    print("")

profiles = {}

print("Number of MAC detectesd", len(sorted_mac))
for mac, packet_list in sorted_mac:
    if mac is not None:
        layers = {}
        patient_ids = {}
        pcap_files = {}
        packet_profile = {}
        for packet in packet_list:
            pydict_count(layers, packet.layers)
            pydict_count(patient_ids, packet.patient_id)
            pydict_count(pcap_files, packet.pcap_file)
            pydict_count(packet_profile , check_packet(packet))
        explained = True
        profile_trace = list(packet_profile.keys())
        profile_trace.sort()
        profile_trace = " ".join(profile_trace)
        for profile in packet_profile:
            if profile[0] == '?':
                explained = False
        if len(patient_ids) > 1:
            explained = True # A MAC on more than on patient is not valide by definition
        pydict_list(profiles, profile_trace, {
            "mac": mac,
            "patient_ids" :patient_ids,
            "explained": explained
        })
        if not explained:
            print(mac, len(packet_list))
            pprint(layers)
            pprint(patient_ids)
            pprint(pcap_files)
            pprint(packet_profile)
            print("")
    # if mac is not None:
        # Extraction des paquets de cette ad

def print_summary(explained, profiles):
    for profile_trace in profiles:
        nb = 0
        for mac_info in profiles[profile_trace]:
            if mac_info["explained"] == explained:
                nb += 1
        if nb > 0:
            print("Profile : %s : %d" %(profile_trace, nb))

# Bilan
print("Summery :")
print("Explainned MAC :")
print_summary(True, profiles)
print("")
print("Unexplained MAC :")
print_summary(False, profiles)
print("Done")
