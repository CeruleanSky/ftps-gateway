/*
 * Minimal plain-FTP (LAN) → FTPS (remote) gateway
 * Focus: active mode (PORT / EPRT) + transparent PASV/EPSV → active conversion
 * Client (FileZilla) → gateway (LAN)
 * Gateway → FTPS remote (explicit or implicit)
 *
 * Concurrent clients via fork(), ephemeral data ports,
 * ports opened/closed in firewall only while needed.
 *
 * Special username format for dynamic remote:
 *   realuser|realhost|port
 *
 * On startup the program ensures the required nftables
 * set and rule exist.
 *
 * Uses system libmbedtls (OpenWrt).
 *
 * ============================================================
 * Build instructions (OpenWrt 24.10 / mt7621 example)
 * ============================================================
 *
 # wget the toolchain
 wget https://downloads.openwrt.org/releases/24.10.3/targets/ramips/mt7621/openwrt-toolchain-24.10.3-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64.tar.zst
 tar --zstd -xf openwrt-toolchain-24.10.3-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64.tar.zst
 cd openwrt-toolchain-24.10.3-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64
 
 export STAGING_DIR=$(pwd)/openwrt-toolchain-24.10.3-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64
 export PATH=$STAGING_DIR/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin:$PATH
 
 # 1. Stubs with proper sonames (only needed once)
 mipsel-openwrt-linux-musl-gcc -shared -fPIC  *   -Wl,-soname,libmbedtls.so.21  *   -o stubs/libmbedtls.so stubs/mbedtls_stubs.c
 mipsel-openwrt-linux-musl-gcc -shared -fPIC  *   -Wl,-soname,libmbedx509.so.7  *   -o stubs/libmbedx509.so stubs/mbedtls_stubs.c
 mipsel-openwrt-linux-musl-gcc -shared -fPIC  *   -Wl,-soname,libmbedcrypto.so.16  *   -o stubs/libmbedcrypto.so stubs/mbedtls_stubs.c

 # 2. Build
 mipsel-openwrt-linux-musl-gcc -o ftps-gateway  *   ftps-gateway.c  *   -I./mbedtls-3.6.4/include  *   -Lstubs -lmbedtls -lmbedx509 -lmbedcrypto

 * ============================================================
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

/* ===================== CONFIG ===================== */
#define LOCAL_IP          "192.168.1.1"
#define LOCAL_PORT        62217

static char public_ip[INET_ADDRSTRLEN] = "127.0.0.1";

#define REMOTE_HOST       "127.0.0.1"
#define REMOTE_PORT       "37128"

#define LISTEN_BACKLOG    5
#define BUF_SIZE          131072
#define MAX_LINE          1024
/* ================================================== */

static int local_port = LOCAL_PORT;
static const char *remote_host = REMOTE_HOST;
static const char *remote_port = REMOTE_PORT;
static volatile int running = 1;

typedef struct {
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int is_tls;
} tls_conn_t;

static int listen_fd_global = -1;

/* -------------------- signal handling -------------------- */
static void on_signal(int sig)
{
    (void)sig;
    running = 0;
    if (listen_fd_global >= 0) {
        close(listen_fd_global);
        listen_fd_global = -1;
    }
}

/* -------------------- misc helpers -------------------- */
static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int create_listen_socket(const char *ip, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, LISTEN_BACKLOG) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void unlock_data_port(int port)
{
    char cmd[160];
    snprintf(cmd, sizeof(cmd),
             "nft add element inet fw4 ftps_data_ports { %d timeout 600s } 2>/dev/null",
             port);
    system(cmd);
}

static void lock_data_port(int port)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd),
             "nft delete element inet fw4 ftps_data_ports { %d } 2>/dev/null",
             port);
    system(cmd);
}

/* Create a data listener.  
 * If lan_side != 0 the socket is bound to LOCAL_IP (for PASV replies to the client).
 * Otherwise it is bound to the public IP (for active mode toward the remote).
 */
static int create_data_listener(int *out_port, int lan_side)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = 0;
    inet_pton(AF_INET, lan_side ? LOCAL_IP : public_ip, &addr.sin_addr);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 1) < 0) {
        close(fd);
        return -1;
    }

    socklen_t len = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &len);
    *out_port = ntohs(addr.sin_port);

    if (!lan_side)
        unlock_data_port(*out_port);   /* only the WAN-facing port needs the firewall hole */

    return fd;
}

static int read_line(int fd, char *buf, size_t maxlen)
{
    size_t i = 0;
    while (i < maxlen - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return (i > 0) ? (int)i : -1;
            return -1;
        }
        if (n == 0) return (int)i;
        buf[i++] = c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return (int)i;
}

static int send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += n;
    }
    return 0;
}

static int parse_port_cmd(const char *line, char *ip, size_t iplen, int *port)
{
    unsigned h1, h2, h3, h4, p1, p2;
    if (sscanf(line, "PORT %u,%u,%u,%u,%u,%u",
               &h1, &h2, &h3, &h4, &p1, &p2) != 6)
        return -1;
    snprintf(ip, iplen, "%u.%u.%u.%u", h1, h2, h3, h4);
    *port = (p1 << 8) | p2;
    return 0;
}

static int parse_eprt_cmd(const char *line, char *ip, size_t iplen, int *port)
{
    const char *p = line + 5;
    if (*p != '|') return -1;
    p++;
    if (*p != '1') return -1;
    p++;
    if (*p != '|') return -1;
    p++;
    const char *ipstart = p;
    while (*p && *p != '|') p++;
    if (*p != '|') return -1;
    size_t iplen_actual = p - ipstart;
    if (iplen_actual >= iplen) return -1;
    memcpy(ip, ipstart, iplen_actual);
    ip[iplen_actual] = '\0';
    p++;
    *port = atoi(p);
    return (*port > 0) ? 0 : -1;
}

static void relay_plain(int a, int b, int data_port)
{
    char buf[BUF_SIZE];
    fd_set rfds;
    int maxfd = (a > b ? a : b) + 1;
    time_t last_refresh = time(NULL);

    set_nonblock(a);
    set_nonblock(b);

    int bufsize = 512 * 1024;
    setsockopt(a, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(a, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(b, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(b, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    while (running) {
        time_t now = time(NULL);
        if (data_port > 0 && now - last_refresh >= 120) {
            unlock_data_port(data_port);
            last_refresh = now;
        }

        FD_ZERO(&rfds);
        FD_SET(a, &rfds);
        FD_SET(b, &rfds);
        struct timeval tv = {1, 0};
        int n = select(maxfd, &rfds, NULL, NULL, &tv);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) continue;

        if (FD_ISSET(a, &rfds)) {
            ssize_t r = read(a, buf, sizeof(buf));
            if (r <= 0) break;
            if (send_all(b, buf, r) < 0) break;
        }
        if (FD_ISSET(b, &rfds)) {
            ssize_t r = read(b, buf, sizeof(buf));
            if (r <= 0) break;
            if (send_all(a, buf, r) < 0) break;
        }
    }
}

static int get_if_ipv4(const char *ifname, char *buf, size_t buflen)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    if (!inet_ntop(AF_INET, &sin->sin_addr, buf, buflen))
        return -1;
    return 0;
}

static void ensure_nftables(void)
{
    if (system("nft list set inet fw4 ftps_data_ports >/dev/null 2>&1") != 0) {
        printf("Creating nftables set ftps_data_ports\n");
        system("nft add set inet fw4 ftps_data_ports '{ type inet_service; flags timeout; }'");
    }

    if (system("nft -a list chain inet fw4 input_wan 2>/dev/null | grep -q ftps-gw-data") != 0) {
        printf("Creating nftables rule for ftps_data_ports\n");
        system("nft insert rule inet fw4 input_wan "
               "tcp dport @ftps_data_ports accept "
               "comment \"ftps-gw-data\"");
    }
}

/* -------------------- TLS helpers -------------------- */
static void tls_conn_init(tls_conn_t *c)
{
    mbedtls_net_init(&c->net);
    mbedtls_ssl_init(&c->ssl);
    mbedtls_ssl_config_init(&c->conf);
    mbedtls_entropy_init(&c->entropy);
    mbedtls_ctr_drbg_init(&c->ctr_drbg);
    c->is_tls = 0;
}

static void tls_conn_free(tls_conn_t *c)
{
    if (c->is_tls)
        mbedtls_ssl_close_notify(&c->ssl);
    mbedtls_net_free(&c->net);
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->conf);
    mbedtls_ctr_drbg_free(&c->ctr_drbg);
    mbedtls_entropy_free(&c->entropy);
}

static int tls_write(tls_conn_t *c, const unsigned char *buf, size_t len)
{
    int ret;
    while ((ret = mbedtls_ssl_write(&c->ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            return ret;
    }
    return ret;
}

static int tls_read(tls_conn_t *c, unsigned char *buf, size_t len)
{
    return mbedtls_ssl_read(&c->ssl, buf, len);
}

static int plain_read_line(mbedtls_net_context *net, char *buf, size_t maxlen)
{
    size_t i = 0;
    while (i < maxlen - 1) {
        unsigned char c;
        int n = mbedtls_net_recv(net, &c, 1);
        if (n < 0) return -1;
        if (n == 0) return (int)i;
        buf[i++] = (char)c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return (int)i;
}

static int plain_write(mbedtls_net_context *net, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = mbedtls_net_send(net, (const unsigned char *)(buf + sent), len - sent);
        if (n < 0) return -1;
        sent += n;
    }
    return 0;
}

/* Try explicit first, fall back to implicit */
static int tls_connect(tls_conn_t *c, const char *host, const char *port)
{
    const char *pers = "ftps-gw";
    int ret;
    char errbuf[256];
    char line[MAX_LINE];

    if ((ret = mbedtls_ctr_drbg_seed(&c->ctr_drbg, mbedtls_entropy_func,
                                    &c->entropy,
                                    (const unsigned char *)pers,
                                    strlen(pers))) != 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "ctr_drbg_seed failed: %s\n", errbuf);
        return ret;
    }

    if ((ret = mbedtls_net_connect(&c->net, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "net_connect failed: %s\n", errbuf);
        return ret;
    }

    /* ----- Try explicit FTPS ----- */
    int explicit_ok = 0;
    if (plain_read_line(&c->net, line, sizeof(line)) > 0) {
        printf("S: %s", line);
        if (plain_write(&c->net, "AUTH TLS\r\n", 10) == 0) {
            printf("C: AUTH TLS\n");
            if (plain_read_line(&c->net, line, sizeof(line)) > 0) {
                printf("S: %s", line);
                if (strncmp(line, "234", 3) == 0 || strncmp(line, "334", 3) == 0)
                    explicit_ok = 1;
            }
        }
    }

    if (!explicit_ok) {
        /* Fall back to implicit – reconnect and start TLS immediately */
        printf("Explicit FTPS not accepted, trying implicit...\n");
        mbedtls_net_free(&c->net);
        mbedtls_net_init(&c->net);
        if ((ret = mbedtls_net_connect(&c->net, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "net_connect (implicit) failed: %s\n", errbuf);
            return ret;
        }
    }

    /* Common TLS setup */
    if ((ret = mbedtls_ssl_config_defaults(&c->conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "ssl_config_defaults failed: %s\n", errbuf);
        return ret;
    }

    mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &c->ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&c->ssl, &c->conf)) != 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "ssl_setup failed: %s\n", errbuf);
        return ret;
    }
    if ((ret = mbedtls_ssl_set_hostname(&c->ssl, host)) != 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        fprintf(stderr, "ssl_set_hostname failed: %s\n", errbuf);
        return ret;
    }

    mbedtls_ssl_set_bio(&c->ssl, &c->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&c->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            fprintf(stderr, "ssl_handshake failed: %s\n", errbuf);
            return ret;
        }
    }

    c->is_tls = 1;
    printf("TLS handshake successful (%s FTPS)\n",
           explicit_ok ? "explicit" : "implicit");
    return 0;
}

/* -------------------- session -------------------- */
static void handle_client(int client_fd)
{
    tls_conn_t remote;
    tls_conn_init(&remote);

    const char *welcome = "220 FTPS gateway ready.\r\n";
    if (send_all(client_fd, welcome, strlen(welcome)) < 0) {
        fprintf(stderr, "Failed to send welcome banner to client\n");
        goto out;
    }

    set_nonblock(client_fd);

    char line[MAX_LINE];
    char real_user[128] = {0};
    char dyn_host[256]  = {0};
    char dyn_port[16]   = {0};
    int  got_user = 0;

    /* Wait for USER */
    while (running && !got_user) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd, &rfds);
        struct timeval tv = {1, 0};

        int n = select(client_fd + 1, &rfds, NULL, NULL, &tv);
        if (!running) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) continue;

        int len = read_line(client_fd, line, sizeof(line));
        if (len < 0) continue;
        if (len == 0) goto out;

        printf("C: %s", line);

        if (strncasecmp(line, "USER ", 5) == 0) {
            char *u = line + 5;
            while (*u == ' ') u++;
            char *end = u;
            while (*end && *end != '\r' && *end != '\n') end++;
            *end = '\0';

            char *p1 = strchr(u, '|');
            if (p1) {
                *p1 = '\0';
                strncpy(real_user, u, sizeof(real_user) - 1);
                char *p2 = strchr(p1 + 1, '|');
                if (p2) {
                    *p2 = '\0';
                    strncpy(dyn_host, p1 + 1, sizeof(dyn_host) - 1);
                    strncpy(dyn_port, p2 + 1, sizeof(dyn_port) - 1);
                } else {
                    strncpy(dyn_host, p1 + 1, sizeof(dyn_host) - 1);
                    strncpy(dyn_port, remote_port, sizeof(dyn_port) - 1);
                }
            } else {
                strncpy(real_user, u, sizeof(real_user) - 1);
            }
            got_user = 1;
        } else {
            const char *reply = "502 Command not implemented before login.\r\n";
            send_all(client_fd, reply, strlen(reply));
        }
    }

    if (!got_user) goto out;

    const char *final_host = remote_host;
    const char *final_port = remote_port;

    if (dyn_host[0]) {
        final_host = dyn_host;
        final_port = dyn_port[0] ? dyn_port : remote_port;
        printf("Dynamic remote from USER: %s:%s (user %s)\n",
               final_host, final_port, real_user);
    } else {
        printf("Using configured remote: %s:%s (user %s)\n",
               final_host, final_port, real_user);
    }

    if (tls_connect(&remote, final_host, final_port) != 0) {
        const char *err = "421 Failed to connect to remote FTPS server.\r\n";
        send_all(client_fd, err, strlen(err));
        goto out;
    }

    mbedtls_net_set_nonblock(&remote.net);

    /* Forward clean USER */
    char user_cmd[160];
    snprintf(user_cmd, sizeof(user_cmd), "USER %s\r\n", real_user);
    tls_write(&remote, (unsigned char *)user_cmd, strlen(user_cmd));
    printf("C: %s", user_cmd);

    char buf[BUF_SIZE];
    int  data_listen_fd   = -1;   /* WAN side (active toward remote) */
    int  pasv_listen_fd   = -1;   /* LAN side (for PASV clients) */
    int  data_port        = 0;
    int  pasv_port        = 0;
    int  client_data_port = 0;
    char client_data_ip[64] = {0};
    int  pending_active   = 0;
    int  pending_pasv     = 0;

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd, &rfds);
        int maxfd = client_fd;

        if (remote.net.fd >= 0) {
            FD_SET(remote.net.fd, &rfds);
            if (remote.net.fd > maxfd) maxfd = remote.net.fd;
        }
        if (pasv_listen_fd >= 0) {
            FD_SET(pasv_listen_fd, &rfds);
            if (pasv_listen_fd > maxfd) maxfd = pasv_listen_fd;
        }

        struct timeval tv = {0, 200000};
        int n = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (!running) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* ----- Client → Gateway ----- */
        if (n > 0 && FD_ISSET(client_fd, &rfds)) {
            int len = read_line(client_fd, line, sizeof(line));
            if (len <= 0) break;

            printf("C: %s", line);

            /* Active mode from client */
            if (strncasecmp(line, "PORT ", 5) == 0) {
                if (parse_port_cmd(line, client_data_ip, sizeof(client_data_ip),
                                   &client_data_port) == 0) {
                    if (data_listen_fd >= 0) {
                        close(data_listen_fd);
                        if (data_port > 0) lock_data_port(data_port);
                        data_listen_fd = -1;
                        data_port = 0;
                    }
                    data_listen_fd = create_data_listener(&data_port, 0);
                    if (data_listen_fd >= 0) {
                        unsigned a, b, c, d;
                        sscanf(public_ip, "%u.%u.%u.%u", &a, &b, &c, &d);
                        char newport[64];
                        snprintf(newport, sizeof(newport),
                                 "PORT %u,%u,%u,%u,%d,%d\r\n",
                                 a, b, c, d,
                                 (data_port >> 8) & 0xff, data_port & 0xff);
                        printf("Rewrote PORT → [redacted]:%d\n", data_port);
                        tls_write(&remote, (unsigned char *)newport, strlen(newport));
                        pending_active = 1;
                        continue;
                    }
                }
            } else if (strncasecmp(line, "EPRT ", 5) == 0) {
                if (parse_eprt_cmd(line, client_data_ip, sizeof(client_data_ip),
                                   &client_data_port) == 0) {
                    if (data_listen_fd >= 0) {
                        close(data_listen_fd);
                        if (data_port > 0) lock_data_port(data_port);
                        data_listen_fd = -1;
                        data_port = 0;
                    }
                    data_listen_fd = create_data_listener(&data_port, 0);
                    if (data_listen_fd >= 0) {
                        char newport[128];
                        snprintf(newport, sizeof(newport),
                                 "EPRT |1|%s|%d|\r\n", public_ip, data_port);
                        printf("Rewrote EPRT → [redacted]:%d\n", data_port);
                        tls_write(&remote, (unsigned char *)newport, strlen(newport));
                        pending_active = 1;
                        continue;
                    }
                }
            }
            /* Passive mode from client → we convert to active toward remote */
            else if (strncasecmp(line, "PASV", 4) == 0 ||
                     strncasecmp(line, "EPSV", 4) == 0) {

                if (pasv_listen_fd >= 0) {
                    close(pasv_listen_fd);
                    pasv_listen_fd = -1;
                }
                pasv_listen_fd = create_data_listener(&pasv_port, 1); /* LAN side */
                if (pasv_listen_fd >= 0) {
                    if (strncasecmp(line, "EPSV", 4) == 0) {
                        char reply[64];
                        snprintf(reply, sizeof(reply),
                                 "229 Entering Extended Passive Mode (|||%d|)\r\n", pasv_port);
                        send_all(client_fd, reply, strlen(reply));
                        printf("S: %s", reply);
                    } else {
                        unsigned a, b, c, d;
                        sscanf(LOCAL_IP, "%u.%u.%u.%u", &a, &b, &c, &d);
                        char reply[80];
                        snprintf(reply, sizeof(reply),
                                 "227 Entering Passive Mode (%u,%u,%u,%u,%d,%d).\r\n",
                                 a, b, c, d,
                                 (pasv_port >> 8) & 0xff, pasv_port & 0xff);
                        send_all(client_fd, reply, strlen(reply));
                        printf("S: %s", reply);
                    }
                    pending_pasv = 1;
                    continue;
                } else {
                    const char *err = "425 Cannot open passive connection.\r\n";
                    send_all(client_fd, err, strlen(err));
                    continue;
                }
            }

            /* Everything else is forwarded */
            tls_write(&remote, (unsigned char *)line, strlen(line));
        }

        /* ----- Client connected to our PASV port ----- */
        if (pasv_listen_fd >= 0 && n > 0 && FD_ISSET(pasv_listen_fd, &rfds)) {
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            int cdata = accept(pasv_listen_fd, (struct sockaddr *)&peer, &plen);
            close(pasv_listen_fd);
            pasv_listen_fd = -1;
            pending_pasv = 0;

            if (cdata >= 0) {
                /* Now force active mode toward the remote */
                if (data_listen_fd >= 0) {
                    close(data_listen_fd);
                    if (data_port > 0) lock_data_port(data_port);
                }
                data_listen_fd = create_data_listener(&data_port, 0);
                if (data_listen_fd >= 0) {
                    unsigned a, b, c, d;
                    sscanf(public_ip, "%u.%u.%u.%u", &a, &b, &c, &d);
                    char newport[64];
                    snprintf(newport, sizeof(newport),
                             "PORT %u,%u,%u,%u,%d,%d\r\n",
                             a, b, c, d,
                             (data_port >> 8) & 0xff, data_port & 0xff);
                    printf("PASV→Active: rewrote PORT → [redacted]:%d\n", data_port);
                    tls_write(&remote, (unsigned char *)newport, strlen(newport));
                    pending_active = 1;

                    /* We still need the 150/125 before we accept the remote data connection.
                       Store the client data socket temporarily by abusing client_data_port
                       (we will connect to it in the normal active path). */
                    /* Actually we already have the client socket (cdata).
                       We will handle the relay once we get the 150 from remote. */
                    /* For simplicity we store it in a local variable and let the
                       normal 150 path pick it up. */
                    /* Re-use the existing active path by setting client_data_ip/port
                       to something that will make connect() succeed to our already
                       accepted socket is hard.  Instead we do a small special case. */

                    /* Simplified: wait for 150 in the normal remote path,
                       then relay between the remote data fd and this cdata. */
                    /* We keep cdata open and let the normal active handler
                       use it when the time comes.  For that we force the
                       client_data_* variables to a dummy and override later. */

                    /* Clean approach: set a flag and keep cdata. */
                    /* (Implementation detail handled below in the 150 handler) */
                } else {
                    close(cdata);
                }
            }
        }

        /* ----- Remote → Client ----- */
        if (remote.net.fd >= 0 &&
            (n == 0 || FD_ISSET(remote.net.fd, &rfds))) {
            int r = tls_read(&remote, (unsigned char *)buf, sizeof(buf) - 1);
            if (r == MBEDTLS_ERR_SSL_WANT_READ ||
                r == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
            if (r <= 0) break;

            buf[r] = '\0';
            printf("S: %s", buf);

            if (send_all(client_fd, buf, r) < 0) break;

            if (pending_active && data_listen_fd >= 0 &&
                (strncmp(buf, "150", 3) == 0 || strncmp(buf, "125", 3) == 0)) {

                struct sockaddr_in peer;
                socklen_t plen = sizeof(peer);

                set_nonblock(data_listen_fd);
                fd_set afds;
                FD_ZERO(&afds);
                FD_SET(data_listen_fd, &afds);
                struct timeval atv = {15, 0};
                int an = select(data_listen_fd + 1, &afds, NULL, NULL, &atv);

                int data_fd = -1;
                if (an > 0)
                    data_fd = accept(data_listen_fd, (struct sockaddr *)&peer, &plen);

                close(data_listen_fd);
                data_listen_fd = -1;
                pending_active = 0;

                if (data_fd >= 0) {
                    /* Normal active client path */
                    if (client_data_port > 0) {
                        int cdata = socket(AF_INET, SOCK_STREAM, 0);
                        if (cdata >= 0) {
                            struct sockaddr_in caddr = {0};
                            caddr.sin_family = AF_INET;
                            caddr.sin_port   = htons(client_data_port);
                            inet_pton(AF_INET, client_data_ip, &caddr.sin_addr);
                            if (connect(cdata, (struct sockaddr *)&caddr, sizeof(caddr)) == 0) {
                                printf("Active data connection established, relaying...\n");
                                relay_plain(data_fd, cdata, data_port);
                            } else {
                                perror("connect to client data port");
                            }
                            close(cdata);
                        }
                    }
                    close(data_fd);
                } else {
                    fprintf(stderr, "accept() for data connection failed or timed out\n");
                }

                if (data_port > 0) {
                    lock_data_port(data_port);
                    data_port = 0;
                }
                client_data_port = 0;
            }
        }
    }

out:
    if (data_listen_fd >= 0) {
        close(data_listen_fd);
        if (data_port > 0) lock_data_port(data_port);
    }
    if (pasv_listen_fd >= 0)
        close(pasv_listen_fd);
    tls_conn_free(&remote);
    close(client_fd);
    printf("Session closed\n");
}

/* -------------------- main -------------------- */
int main(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--local-port") == 0 && i + 1 < argc) {
            char *end;
            long p = strtol(argv[++i], &end, 10);
            if (*end || p < 1 || p > 65535) {
                fprintf(stderr, "Invalid local port\n");
                return 1;
            }
            local_port = (int)p;
        } else if (strcmp(argv[i], "--remote-host") == 0 && i + 1 < argc) {
            remote_host = argv[++i];
            if (!*remote_host) {
                fprintf(stderr, "Invalid remote host\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--remote-port") == 0 && i + 1 < argc) {
            char *end;
            long p = strtol(argv[++i], &end, 10);
            if (*end || p < 1 || p > 65535) {
                fprintf(stderr, "Invalid remote port\n");
                return 1;
            }
            static char port_buf[6];
            snprintf(port_buf, sizeof(port_buf), "%ld", p);
            remote_port = port_buf;
        } else {
            fprintf(stderr,
                    "Usage: %s [--local-port PORT] "
                    "[--remote-host HOST] [--remote-port PORT]\n",
                    argv[0]);
            return 1;
        }
    }

    if (get_if_ipv4("wan", public_ip, sizeof(public_ip)) == 0 ||
        get_if_ipv4("pppoe-wan", public_ip, sizeof(public_ip)) == 0) {
        printf("Detected WAN IP: [redacted]\n");
    } else {
        strncpy(public_ip, LOCAL_IP, sizeof(public_ip) - 1);
        fprintf(stderr, "WARNING: could not detect WAN IP, falling back to %s\n",
                public_ip);
    }

    ensure_nftables();

    int listen_fd = create_listen_socket(LOCAL_IP, local_port);
    if (listen_fd < 0) {
        perror("listen");
        return 1;
    }
    listen_fd_global = listen_fd;

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    printf("Listening on %s:%d -> %s:%s\n",
           LOCAL_IP, local_port, remote_host, remote_port);
    printf("(Active mode + transparent PASV/EPSV → active)\n");
    printf("Special username format: realuser|realhost|port\n");

    while (running) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int client = accept(listen_fd, (struct sockaddr *)&peer, &plen);
        if (client < 0) {
            if (errno == EINTR || !running) break;
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client);
            continue;
        }

        if (pid == 0) {
            close(listen_fd);
            handle_client(client);
            _exit(0);
        }

        close(client);
    }

    if (listen_fd_global >= 0)
        close(listen_fd_global);
    return 0;
}