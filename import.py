from struct import pack
import sys
import os
from scapy.all import *
from elasticsearch import Elasticsearch
import database

es = Elasticsearch()

pdu_type_dict={}

def disect_file(file_path, action, source, patient_id):
    global pdu_type_dict
    packets = rdpcap(file_path)
    print("Disect", file_path, len(packets))
    for packet in packets:
        packet_db = database.Packet(
            pcap_file=file_path,
            patient_id=patient_id,
            source=source,
            layers=packet.summary(),
            raw=raw(packet).hex(),
            timestamp=packet.time,
            action=action
        )
        # On recherche les packet d'advertising
        if packet.haslayer(BTLE):
            btle_packet = BTLE(raw(packet[BTLE]))
            crc_str = b'\x00' + BTLE.compute_crc(raw(btle_packet.payload))
            crc_int = struct.unpack(">I", crc_str)[0]
            packet_db.crc = (btle_packet.crc == crc_int)
            if packet_db.crc and btle_packet.haslayer(BTLE_ADV):
                adv = btle_packet[BTLE_ADV]
                packet_db.pdu_type = adv.PDU_type
                # On recherche les packets ADV_IND
                if adv.PDU_type in [0, 1, 2]: # ADV_IND, ADV_NONCONN_IND
                    if btle_packet.haslayer(BTLE_ADV_IND):
                        adv_ind = btle_packet[BTLE_ADV_IND]
                    elif btle_packet.haslayer(BTLE_ADV_NONCONN_IND):
                        adv_ind = btle_packet[BTLE_ADV_NONCONN_IND]
                    elif btle_packet.haslayer(BTLE_ADV_DIRECT_IND):
                        adv_ind = btle_packet[BTLE_ADV_DIRECT_IND]
                    else:
                        btle_packet.show2()
                        raise Exception("Packet PDU_TYPE 1 or 2 missing header")
                    packet_db.mac = adv_ind.AdvA
                    # Contrôle de cohérence de la longueur des données
                    try:
                        for data in adv_ind.data:
                            packet_db.valid = (data.len == len(raw(data.payload))+1)
                    except:
                        pass
                    # Recherche de UUID Tout Anti Covid !
                    if btle_packet.haslayer(EIR_CompleteList128BitServiceUUIDs):
                        if len(btle_packet[EIR_CompleteList128BitServiceUUIDs].svc_uuids) > 0:
                            uuid = btle_packet[EIR_CompleteList128BitServiceUUIDs].svc_uuids[0]
                            if uuid == UUID('0000fd64-0000-1000-8000-00805f9b34fb'):
                                packet_db.profile = "uuid_fd64"
                if adv.PDU_type == 3: # SCAN_REQ
                    scan_req = btle_packet[BTLE_SCAN_REQ]
                    packet_db.mac = scan_req.ScanA
                if adv.PDU_type == 4: # SCAN_RSP
                    scan_resp = btle_packet[BTLE_SCAN_RSP]
                    packet_db.mac = scan_resp.AdvA


        if not database.add_Commit(packet_db):
            print("ERROR : Unable to add pakcet into db", packet_db)
        # body={
        #     "source": packet_db.source,
        #     "patient_id": packet_db.patient_id,
        #     "layer": packet.summary(),
        #     "timestamp": datetime.fromtimestamp(packet_db.time),
        #     "pdu_type": packet_db.pdu_type,
        #     "crc": packet_db.crc,
        #     "mac": packet_db.mac,
        #     "valid": packet_db.valid,
        #     "profile": packet_db.profile
        # }
        # es.index(
        #     index="xbt-index-3",
        #     doc_type="pcap",
        #     body=body
        #     )
    # sys.exit(-1)

# Exploration des fichiers pcap
def explore_files(base_dir, action, source, patient_id):
    for files in os.listdir(base_dir):
        files = base_dir + files
        if os.path.isdir(files):
            explore_files(files+"/", action, source, patient_id)
        elif files[-5:] == ".pcap":
            disect_file(files, action, source, patient_id)
        elif files[-7:] == ".pcapng":
            disect_file(files, action, source, patient_id)

def explore_patients_files(base_dir, action, source):
    for patient_id in os.listdir(base_dir):
        files = base_dir + patient_id
        if os.path.isdir(files):
            explore_files(files+"/", action, source, action+"_"+patient_id)
        else:
            print("ERROR is note dir", files)

# explore_patients_files("./capture/pays-basque-j1/damien/", "pays-basque-j1", "damien")
# explore_patients_files("./capture/pays-basque-j1/olivier/", "pays-basque-j1", "olivier")
# explore_patients_files("./capture/pays-basque-j2/damien/", "pays-basque-j2", "damien")
# explore_patients_files("./capture/pays-basque-j2/olivier/", "pays-basque-j2", "olivier")
explore_patients_files("./capture/haute-savoie/", "haute-savoie", "damien")
# explore_files("./capture/limoge/", "limoge", "limoge", "limoge_?")

print("Ended")