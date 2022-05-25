TARGETS = legitimate-ca-pubkey.pem legitimate-packet.data legitimate-psk.data legitimate-psk.sha256 legitimate-psk-signature.sha256 invalid-psk.data invalid-psk-packet.data invalid-psk-signature.sha256 invalid-psk-signature-packet.data invalid-ca-key.pem unknown-referring-node.data legitimate-ca.pem legitimate-csr.csr wireguard-privkey.key wireguard-pubkey.key wireguard-pubkey.data legitimate-csr.signed.csr legitimate-response-packet.data

PD = $(shell PATH=$(PATH) which pd)
OPENSSL = $(shell PATH=$(PATH) which openssl)

all: $(TARGETS)

%.data: %.protodata
	$(PD) $< -o $@

%-pubkey.pem: %-key.pem
	$(OPENSSL) rsa -pubout -out $@ -in $<

%.sha256: %.data
	$(OPENSSL) dgst -sha256 -binary -out $@ $<

%.signed.csr: %.csr legitimate-ca-key.pem
	# Sign with a 900 day expiry
	$(OPENSSL) x509 -req -days 900 -in $< -signkey legitimate-ca-key.pem -out $@

.PHONY: clean

clean:
	rm -f $(TARGETS)

legitimate-psk-signature.sha256: legitimate-psk.data legitimate-ca-key.pem
	$(OPENSSL) dgst -sha256 -binary -sign legitimate-ca-key.pem -out $@ < $<

legitimate-packet.data: legitimate-packet.protodata legitimate-psk.sha256 legitimate-psk-signature.sha256 legitimate-csr.csr

invalid-psk.data: legitimate-psk.data
	tail -c -1 $< > $@
	head -c 1 $< >> $@

invalid-psk-packet.data: invalid-psk-packet.protodata invalid-psk.sha256
	$(PD) $< -o $@

invalid-ca-key.pem:
	$(OPENSSL) genrsa -out $@ 2048

invalid-psk-signature.sha256: legitimate-psk.data invalid-ca-key.pem
	$(OPENSSL) dgst -sha256 -binary -sign invalid-ca-key.pem -out $@ < $<

invalid-psk-signature-packet.data: invalid-psk-signature-packet.protodata invalid-psk-signature.sha256

unknown-referring-node.data: unknown-referring-node.protodata legitimate-psk.sha256 legitimate-psk-signature.sha256 legitimate-csr.csr

legitimate-ca.pem: legitimate-ca-key.pem
	# Set a validity of 1000 days for root CA certificate
	$(OPENSSL) req -x509 -nodes -key $< -out $@ -sha256 -days 1000 -subj "/C=GB/ST=Test CA State/L=Test CA City/O=Test CA Organisation/OU=Test CA Organisational Unit/CN=Test CA Common Name"

legitimate-csr.csr: legitimate-csr-key.pem
	$(OPENSSL) req -new -nodes -key $< -out $@ -subj "/C=GB/ST=Test State/L=Test City/O=Test Organisation/OU=Test Organisational Unit/CN=Test Common Name"

wireguard-privkey.key:
	wg genkey > $@

wireguard-pubkey.key: wireguard-privkey.key
	wg pubkey < $< > $@

wireguard-pubkey.data: wireguard-pubkey.key
	base64 -d $< > $@

legitimate-response-packet.data: legitimate-response-packet.protodata wireguard-pubkey.data legitimate-csr.signed.csr
