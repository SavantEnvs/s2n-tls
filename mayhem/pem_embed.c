/* Serves the test PEMs the harnesses open as "../pems/..." from the binary itself. Mayhem runs a
 * target from its own cwd, where that relative path does not exist, so s2n_read_test_pem() fails in
 * s2n_fuzz_init and the fuzzer keeps running with no certificate. Linked with
 * -Wl,--wrap=fopen -Wl,--wrap=X509_STORE_load_locations; any other path falls through to libc. */
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define EMBED(sym, rel)                                                            \
    extern const unsigned char sym[], sym##_end[];                                 \
    __asm__(".pushsection .rodata\n.globl " #sym "\n.globl " #sym "_end\n" #sym ":\n" \
            ".incbin \"" PEM_DIR "/" rel "\"\n" #sym "_end:\n.popsection")

EMBED(pem_rsa_chain, "permutations/rsae_pkcs_2048_sha256/server-chain.pem");
EMBED(pem_rsa_key, "permutations/rsae_pkcs_2048_sha256/server-key.pem");
EMBED(pem_dhparams, "dhparams_2048.pem");
EMBED(pem_ocsp_ca, "ocsp/ca_cert.pem");
EMBED(pem_ocsp_server, "ocsp/server_cert.pem");

static const struct {
    const char *path;
    const unsigned char *start, *end;
} PEMS[] = {
    { "../pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem", pem_rsa_chain, pem_rsa_chain_end },
    { "../pems/permutations/rsae_pkcs_2048_sha256/server-key.pem", pem_rsa_key, pem_rsa_key_end },
    { "../pems/dhparams_2048.pem", pem_dhparams, pem_dhparams_end },
    { "../pems/ocsp/ca_cert.pem", pem_ocsp_ca, pem_ocsp_ca_end },
    { "../pems/ocsp/server_cert.pem", pem_ocsp_server, pem_ocsp_server_end },
};

static int find(const char *path)
{
    if (!path) {
        return -1;
    }
    for (size_t i = 0; i < sizeof(PEMS) / sizeof(PEMS[0]); i++) {
        if (strcmp(path, PEMS[i].path) == 0) {
            return (int) i;
        }
    }
    return -1;
}

extern FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode)
{
    int i = find(path);
    if (i >= 0 && mode && mode[0] == 'r') {
        return fmemopen((void *) PEMS[i].start, PEMS[i].end - PEMS[i].start, "rb");
    }
    return __real_fopen(path, mode);
}

extern int __real_X509_STORE_load_locations(X509_STORE *ctx, const char *file, const char *dir);
int __wrap_X509_STORE_load_locations(X509_STORE *ctx, const char *file, const char *dir)
{
    int i = find(file);
    if (i < 0 || dir != NULL) {
        return __real_X509_STORE_load_locations(ctx, file, dir);
    }
    BIO *bio = BIO_new_mem_buf(PEMS[i].start, (int) (PEMS[i].end - PEMS[i].start));
    if (!bio) {
        return 0;
    }
    int loaded = 0;
    X509 *cert = NULL;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        loaded += X509_STORE_add_cert(ctx, cert) == 1;
        X509_free(cert);
    }
    ERR_clear_error();
    BIO_free(bio);
    return loaded > 0;
}
