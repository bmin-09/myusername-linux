#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// Function to check if the certificate's issuer matches the filter
int check_issuer(X509 *cert, const char *issuer_filter) {
    X509_NAME *issuer_name = X509_get_issuer_name(cert);
    char issuer[256];
    
    // Get the issuer's common name (CN)
    if (X509_NAME_get_text_by_NID(issuer_name, NID_commonName, issuer, sizeof(issuer)) < 0) {
        fprintf(stderr, "Failed to get issuer's common name\n");
        return 0;
    }
    
    // Compare issuer with the filter string
    if (strstr(issuer, issuer_filter) != NULL) {
        return 1; // Match found
    }
    return 0; // No match
}

void filter_certificates(const char *file_path, const char *issuer_filter) {
    FILE *cert_file = fopen(file_path, "r");
    if (!cert_file) {
        perror("Unable to open certificate file");
        return;
    }

    // Initialize OpenSSL libraries
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Error loading certificate\n");
        fclose(cert_file);
        return;
    }

    // Check the issuer
    if (check_issuer(cert, issuer_filter)) {
        printf("Certificate matches the issuer filter!\n");
        X509_print_fp(stdout, cert);
    } else {
        printf("Certificate does not match the issuer filter.\n");
    }

    // Clean up
    X509_free(cert);
    fclose(cert_file);
}

int main() {
    const char *cert_file_path = "certificate.pem";  // Path to the certificate file
    const char *issuer_filter = "Example CA";         // Issuer to filter by

    filter_certificates(cert_file_path, issuer_filter);

    return 0;
}
