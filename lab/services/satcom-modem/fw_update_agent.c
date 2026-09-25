/*
 * fw_update_agent.c -- Satellite Communications Modem Firmware Update Agent
 *
 * Listens on TCP 9000. Accepts two commands:
 *   STATUS            -> print version and ready state
 *   UPDATE <url>      -> fetch firmware from <url> and execute it
 *
 * Intentional misconfigurations (no CVEs):
 *   MC-MODEM-1  No authentication on the update interface
 *   MC-MODEM-2  URL passed directly to wget with no validation or signature check
 *   MC-MODEM-3  Downloaded binary executed immediately with no integrity verification
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT     9000
#define BUFSIZE  1024
#define URLSIZE  512

static void handle_client(int fd)
{
    char buf[BUFSIZE];
    int  n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = '\0';

    /* strip trailing whitespace */
    for (int i = n - 1; i >= 0 && (buf[i] == '\n' || buf[i] == '\r' || buf[i] == ' '); i--)
        buf[i] = '\0';

    if (strncmp(buf, "STATUS", 6) == 0) {
        dprintf(fd, "FW-UPDATE-AGENT v1.0\r\nModel: OrsuComm-9400\r\nStatus: READY\r\n");

    } else if (strncmp(buf, "UPDATE ", 7) == 0) {
        char url[URLSIZE];
        strncpy(url, buf + 7, sizeof(url) - 1);
        url[sizeof(url) - 1] = '\0';

        dprintf(fd, "UPDATE: fetching firmware from %s\r\n", url);
        fflush(NULL);

        /* No authentication. No signature check. No URL allowlist. */
        char fetch_cmd[BUFSIZE + URLSIZE];
        snprintf(fetch_cmd, sizeof(fetch_cmd),
                 "wget -q -O /tmp/fw_update.bin \"%s\"", url);
        if (system(fetch_cmd) != 0) {
            dprintf(fd, "ERROR: fetch failed\r\n");
            return;
        }

        system("chmod +x /tmp/fw_update.bin");
        dprintf(fd, "UPDATE: executing firmware image\r\n");
        fflush(NULL);

        /* Execute with no integrity verification */
        system("/tmp/fw_update.bin &");
        dprintf(fd, "UPDATE COMPLETE\r\n");

    } else {
        dprintf(fd, "Commands: STATUS, UPDATE <url>\r\n");
    }
}

int main(void)
{
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(PORT),
    };
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, 5);
    printf("fw-update-agent listening on TCP %d (no auth — MC-MODEM-1)\n", PORT);
    fflush(stdout);

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int fd = accept(srv, (struct sockaddr *)&peer, &plen);
        if (fd < 0) continue;
        printf("connect from %s\n", inet_ntoa(peer.sin_addr));
        fflush(stdout);
        handle_client(fd);
        close(fd);
    }
    return 0;
}
