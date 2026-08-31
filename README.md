# ephemeral-ca

Generates a short-lived CA with server and client certificates for testing mutual TLS.

## What it does

Creates a CA in one directory and issues leaf certificates signed by it, in a
single command. Server certificates carry only the serverAuth extended key
usage and the requested subject alternative names. Client certificates carry
only the clientAuth extended key usage, and their common name is the sole
identifier. Issued certificates are valid for 24 hours by default.

The CA is reused when the output directory already contains one, so adding
another client later signs it with the same CA. There is no revocation, no CRL
publishing, and no way to delete anything. This is a tool for throwaway test
material, not for operating a certificate authority.

## Usage

Issue a CA, a server certificate and two client certificates:

    $ ephemeral-ca -out ./testca -server squid.test,localhost,127.0.0.1 -clients alice,bob
    created CA   testca/ca.crt (expires 2026-09-30T02:22:38Z)
    issued serv  testca/server/squid.test.crt (SAN squid.test, localhost, 127.0.0.1)
    issued clnt  testca/clients/alice.crt (CN alice)
    issued clnt  testca/clients/bob.crt (CN bob)
    certs expire 2026-09-01T02:22:38Z

The resulting layout:

    testca/
      ca.crt
      ca.key
      server/
        squid.test.crt
        squid.test.key
      clients/
        alice.crt
        alice.key
        bob.crt
        bob.key

Add another client against the same CA:

    $ ephemeral-ca -out ./testca -clients carol
    reusing CA   testca/ca.crt (expires 2026-09-30T02:22:38Z)
    issued clnt  testca/clients/carol.crt (CN carol)
    certs expire 2026-09-01T02:22:59Z

Whether the CA was created or reused is always printed, because a silently
reused CA is the most confusing way for a test to go wrong.

Re-running with a name that already exists overwrites that certificate and key.
Refreshing expired test material is the common case, so this is not guarded.

### Flags

    -out string       Output directory (default "./ephemeral-ca")
    -server string    Comma separated DNS names and IP addresses for one server certificate
    -clients string   Comma separated common names, one client certificate each
    -ttl duration     Validity of issued server and client certificates (default 24h0m0s)
    -ca-ttl duration  Validity of the CA certificate, used only when the CA is created (default 720h0m0s)
    -version          Print version and exit

Values that parse as an IP address become IP subject alternative names, and
everything else becomes a DNS name. The common name of the server certificate
is the first value given to -server.

Issuing a certificate that would outlive the CA is an error rather than a
warning:

    $ ephemeral-ca -out ./testca -clients dave -ttl 8760h
    reusing CA   testca/ca.crt (expires 2026-09-30T02:22:38Z)
    Error: -ttl would outlive the CA (certs 2027-08-31T02:22:59Z, CA 2026-09-30T02:22:38Z): shorten -ttl or delete ./testca and start over

### Verifying the output

    $ openssl verify -CAfile testca/ca.crt -purpose sslserver testca/server/squid.test.crt
    testca/server/squid.test.crt: OK

    $ openssl verify -CAfile testca/ca.crt -purpose sslclient testca/clients/alice.crt
    testca/clients/alice.crt: OK

The two profiles are disjoint, so a client certificate FAILs verification for a
server purpose. This is deliberate: an extended key usage mistake in the
configuration under test should surface here rather than in production.

    $ openssl verify -CAfile testca/ca.crt -purpose sslserver testca/clients/alice.crt
    error 26 at 0 depth lookup: unsuitable certificate purpose
    error testca/clients/alice.crt: verification failed

A full handshake against the generated material:

    $ openssl s_server -accept 14443 -cert testca/server/squid.test.crt \
        -key testca/server/squid.test.key -CAfile testca/ca.crt -Verify 1 -www

    $ openssl s_client -connect 127.0.0.1:14443 -servername squid.test \
        -CAfile testca/ca.crt -cert testca/clients/alice.crt -key testca/clients/alice.key

## Notes

Keys are ECDSA P-256.

Names containing a path separator, and the names "." and "..", are rejected
rather than rewritten, so that the common name in the certificate always
matches the path on disk.

## License

This project is licensed under the [MIT License](LICENSE).
