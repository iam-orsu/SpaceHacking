"""
PUS-C TM secondary header and TM[1,1] TC Acceptance builder (satellite side).
Reference: ECSS-E-ST-70-41C, Sections 5.3.4 and 5.4.2.2

TM secondary header layout (15 bytes):
  Byte 0:   pus_ver_time  = 0x21 (PUS-C, fine time = CDS)
  Byte 1:   service_type
  Byte 2:   service_subtype
  Bytes 3-4: message_counter (uint16)
  Bytes 5-6: destination_id (uint16)
  Bytes 7-14: CDS time (8 bytes)

TM[1,1] TC Acceptance application data (4 bytes):
  Bytes 0-1: accepted TC APID     (uint16)
  Bytes 2-3: accepted TC seq count (uint16)
"""
import struct
from cds import cds_now

_msg_counter = 0


def _build_tm_secondary(svc_type: int, svc_subtype: int,
                        dest_id: int = 0x0000) -> bytes:
    global _msg_counter
    ctr = _msg_counter & 0xFFFF
    _msg_counter += 1
    return (
        struct.pack(">BBBHH", 0x21, svc_type, svc_subtype, ctr, dest_id)
        + cds_now()
    )


def build_tm11(tc_apid: int, tc_seq_count: int) -> bytes:
    """Build a PUS TM[1,1] TC Acceptance Success report payload."""
    sec = _build_tm_secondary(svc_type=1, svc_subtype=1)
    app = struct.pack(">HH", tc_apid & 0x7FF, tc_seq_count & 0x3FFF)
    return sec + app
