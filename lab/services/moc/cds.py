"""
CCSDS Day Segmented (CDS) time format encoder/decoder.
Reference: CCSDS 301.0-B-4, Section 3.3

8-byte format (no P-field):
  Bytes 0-1: days since 1958-01-01 00:00:00 UTC  (uint16)
  Bytes 2-5: milliseconds of day                  (uint32)
  Bytes 6-7: sub-millisecond, microseconds 0-999  (uint16)
"""
import datetime
import struct

_EPOCH = datetime.datetime(1958, 1, 1, tzinfo=datetime.timezone.utc)


def cds_now() -> bytes:
    now   = datetime.datetime.now(datetime.timezone.utc)
    delta = now - _EPOCH
    days  = delta.days
    day_us     = delta.seconds * 1_000_000 + delta.microseconds
    ms_of_day  = day_us // 1000
    sub_ms_us  = day_us % 1000
    return struct.pack("!HIH", days, ms_of_day, sub_ms_us)


def cds_decode(b: bytes) -> dict:
    days, ms_of_day, sub_ms_us = struct.unpack("!HIH", b[:8])
    ts = _EPOCH + datetime.timedelta(
        days=days, milliseconds=ms_of_day, microseconds=sub_ms_us
    )
    return {
        "days":      days,
        "ms_of_day": ms_of_day,
        "sub_ms_us": sub_ms_us,
        "iso":       ts.isoformat(),
        "unix":      ts.timestamp(),
    }
