"""
PUS-C TC secondary header builder (ground station side).
Reference: ECSS-E-ST-70-41C, Section 5.3.3

Secondary header layout (5 bytes):
  Byte 0:    pus_ver_ack = (PUS-C = 0x20) | ack_flags
  Byte 1:    service_type
  Byte 2:    service_subtype
  Bytes 3-4: source_id (uint16 big-endian)

Application data appended (2 bytes):
  Byte 5: func_code
  Byte 6: checksum = XOR(sec_header_bytes + func_code) ^ 0xFF

Total secondary section: 7 bytes -> data_len field = 6
"""
import struct

PUS_VER     = 0x20  # PUS-C: version bits 7:4 = 0b0010
ACK_ACCEPT  = 0x01  # request acceptance verification only


def build_pus_tc_secondary(svc_type: int, svc_subtype: int, func_code: int,
                            source_id: int = 0x0001,
                            ack_flags: int = ACK_ACCEPT) -> bytes:
    pus_ver_ack  = (PUS_VER & 0xF0) | (ack_flags & 0x0F)
    hdr          = struct.pack(">BBBH", pus_ver_ack, svc_type, svc_subtype, source_id)
    ck = 0xFF
    for b in hdr:
        ck ^= b
    ck ^= func_code
    return hdr + bytes([func_code, ck])
