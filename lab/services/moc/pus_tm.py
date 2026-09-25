"""
PUS-C TM[1,1] TC Acceptance parser (MOC side).
Reference: ECSS-E-ST-70-41C, Section 5.4.2.2

Parses the 19-byte PUS TM payload produced by the satellite:
  15 bytes PUS TM secondary header
   4 bytes application data (accepted TC APID + seq)
"""
import struct
from cds import cds_decode

TM11_PAYLOAD_SIZE = 19  # 15-byte PUS secondary + 4-byte app data


def parse_tm11(apid: int, seq_count: int, payload: bytes) -> dict | None:
    if len(payload) < TM11_PAYLOAD_SIZE:
        return None
    pus_ver_time = payload[0]
    svc_type     = payload[1]
    svc_subtype  = payload[2]
    msg_counter  = struct.unpack(">H", payload[3:5])[0]
    dest_id      = struct.unpack(">H", payload[5:7])[0]
    cds_time     = cds_decode(payload[7:15])
    app          = payload[15:]
    if svc_type != 1 or svc_subtype != 1 or len(app) < 4:
        return None
    accepted_apid = struct.unpack(">H", app[0:2])[0]
    accepted_seq  = struct.unpack(">H", app[2:4])[0]
    return {
        "packet_type":   "tm11_acceptance",
        "apid":          apid,
        "seq_count":     seq_count,
        "svc_type":      svc_type,
        "svc_subtype":   svc_subtype,
        "msg_counter":   msg_counter,
        "dest_id":       dest_id,
        "pus_time":      cds_time,
        "accepted_apid": accepted_apid,
        "accepted_seq":  accepted_seq,
    }
