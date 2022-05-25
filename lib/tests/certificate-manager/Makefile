TARGETS = x509-csr.pem private-key.pem invalid-csr.data x509-chain.1.pem x509-chain.2.pem x509-chain.pem

OPENSSL = $(shell PATH=$(PATH) which openssl)

all: $(TARGETS)

.PHONY: clean
clean:
	rm -f $(TARGETS)

private-key.pem:
	$(OPENSSL) genrsa -out $@ 2048

x509-csr.pem: private-key.pem
	$(OPENSSL) req -new -key private-key.pem -nodes -out $@ -subj "/C=GB/ST=State/L=City/O=Organisation/OU=Organisational Unit/CN=Common Name"

invalid-csr.data:
	head -c 600 /dev/urandom > $@

x509-chain.1.pem: private-key.pem
	$(OPENSSL) req -x509 -nodes -key private-key.pem -out $@ -sha256 -days 1000 -subj "/C=GB/ST=Test CA State/L=Test CA City/O=Test CA Organisation/OU=Test CA Organisational Unit/CN=Test CA Common Name"

x509-chain.2.pem: x509-chain.1.pem private-key.pem
	$(OPENSSL) req -new -nodes -newkey rsa:2048 -out "$@.csr" -subj "/C=GB/ST=Test State/L=Test City/O=Test Organisation/OU=Test Organisational Unit/CN=Test Common Name"
	$(OPENSSL) x509 -req -days 1000 -in "$@.csr" -signkey private-key.pem -out $@
	rm -f "$@.csr"

x509-chain.pem: x509-chain.1.pem x509-chain.2.pem
	cat $^ > $@
