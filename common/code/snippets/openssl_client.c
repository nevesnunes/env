#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define HOST "encrypted.google.com"

/**
 * Example SSL client that connects to the HOST defined above,
 * and prints out the raw response to stdout.
 */
int main(int arc, char **argv)
{
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        printf("errored; unable to load context.\n");
        ERR_print_errors_fp(stderr);
        return -3;
    }
    
    BIO *bio = BIO_new_ssl_connect(ctx);
    
    SSL *ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    
    BIO_set_conn_hostname(bio, HOST":https");
    
    if (BIO_do_connect(bio) <= 0) {
        BIO_free_all(bio);
        printf("errored; unable to connect.\n");
        ERR_print_errors_fp(stderr);
        return -2;
    }
    
    const char *request = "GET / HTTP/1.1\nHost: "HOST"\nUser Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\nConnection: Close\n\n";
    
    if (BIO_puts(bio, request) <= 0) {
        BIO_free_all(bio);
        printf("errored; unable to write.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    char tmpbuf[1024+1];
    
    for (;;) {
        int len = BIO_read(bio, tmpbuf, 1024);
        if (len == 0) {
            break;
        }
        else if (len < 0) {
            if (!BIO_should_retry(bio)) {
                printf("errored; read failed.\n");
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        else {
            tmpbuf[len] = 0;
            printf("%s", tmpbuf);
        }
    }
    
    BIO_free_all(bio);
    
    return 0;
}