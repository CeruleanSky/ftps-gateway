/* Minimal stubs so the cross-linker is happy.
   Real implementations come from the router’s libmbedtls at runtime. */


// mipsel-openwrt-linux-musl-gcc -shared -fPIC \
  // -Wl,-soname,libmbedtls.so.21 \
  // -o stubs/libmbedtls.so stubs/mbedtls_stubs.c

// mipsel-openwrt-linux-musl-gcc -shared -fPIC \
  // -Wl,-soname,libmbedx509.so.7 \
  // -o stubs/libmbedx509.so stubs/mbedtls_stubs.c

// mipsel-openwrt-linux-musl-gcc -shared -fPIC \
  // -Wl,-soname,libmbedcrypto.so.16 \
  // -o stubs/libmbedcrypto.so stubs/mbedtls_stubs.c


#include <stddef.h>
#include <stdint.h>

int mbedtls_net_set_nonblock(void *ctx) { return -1;}
void mbedtls_strerror(int ret, char *buf, size_t buflen) {}

void mbedtls_net_init(void *ctx) {}
void mbedtls_net_free(void *ctx) {}
int  mbedtls_net_connect(void *ctx, const char *host, const char *port, int proto) { return -1; }
int  mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len) { return -1; }
int  mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len) { return -1; }

void mbedtls_ssl_init(void *ssl) {}
void mbedtls_ssl_free(void *ssl) {}
int  mbedtls_ssl_setup(void *ssl, const void *conf) { return -1; }
int  mbedtls_ssl_set_hostname(void *ssl, const char *hostname) { return -1; }
void mbedtls_ssl_set_bio(void *ssl, void *p_bio,
                         int (*f_send)(void *, const unsigned char *, size_t),
                         int (*f_recv)(void *, unsigned char *, size_t),
                         int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t)) {}
int  mbedtls_ssl_handshake(void *ssl) { return -1; }
int  mbedtls_ssl_read(void *ssl, unsigned char *buf, size_t len) { return -1; }
int  mbedtls_ssl_write(void *ssl, const unsigned char *buf, size_t len) { return -1; }
int  mbedtls_ssl_close_notify(void *ssl) { return -1; }

void mbedtls_ssl_config_init(void *conf) {}
void mbedtls_ssl_config_free(void *conf) {}
int  mbedtls_ssl_config_defaults(void *conf, int endpoint, int transport, int preset) { return -1; }
void mbedtls_ssl_conf_authmode(void *conf, int authmode) {}
void mbedtls_ssl_conf_rng(void *conf, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {}

void mbedtls_entropy_init(void *ctx) {}
void mbedtls_entropy_free(void *ctx) {}
int  mbedtls_entropy_func(void *data, unsigned char *output, size_t len) { return -1; }

void mbedtls_ctr_drbg_init(void *ctx) {}
void mbedtls_ctr_drbg_free(void *ctx) {}
int  mbedtls_ctr_drbg_seed(void *ctx,
                           int (*f_entropy)(void *, unsigned char *, size_t),
                           void *p_entropy,
                           const unsigned char *custom, size_t len) { return -1; }
int  mbedtls_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len) { return -1; }
