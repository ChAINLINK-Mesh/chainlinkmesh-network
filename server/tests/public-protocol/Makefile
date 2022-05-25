TARGETS = legitimate-init-packet.data legitimate-psk.data legitimate-psk.sha256 legitimate-psk-signature.sha256 legitimate-ca.pem legitimate-csr.csr wireguard-privkey.key wireguard-pubkey.key legitimate-ca-key.pem legitimate-ca-pubkey.pem

PD = $(shell PATH=$(PATH) which pd)
OPENSSL = $(shell PATH=$(PATH) which openssl)

all: $(TARGETS)

%.data: %.protodata
	pd $< -o $@

%-pubkey.pem: %-key.pem
	$(OPENSSL) rsa -pubout -out $@ -in $<

%.sha256: %.data
	$(OPENSSL) dgst -sha256 -binary -out $@ $<

.PHONY: clean

clean:
	rm -f $(TARGETS)

legitimate-psk-signature.sha256: legitimate-psk.data legitimate-ca-key.pem
	$(OPENSSL) dgst -sha256 -binary -sign legitimate-ca-key.pem -out $@ < $<

legitimate-init-packet.data: legitimate-init-packet.protodata legitimate-psk.sha256 legitimate-psk-signature.sha256 legitimate-csr.csr
	$(PD) $< -o $@

legitimate-ca.pem: legitimate-ca-key.pem Makefile
	# Set a validity of 1000 days for root CA certificate
	$(OPENSSL) req -x509 -nodes -key $< -out $@ -sha256 -days 1000 -subj "/C=GB/ST=Test CA State/L=Test CA City/O=Test CA Organisation/OU=Test CA Organisational Unit/CN=Test CA Common Name/UID=VGVzdFdpcmVHdWFyZFB1YmxpY0tleUxpdGVyYWxTdHI\="

legitimate-csr.csr: legitimate-ca-key.pem Makefile
	$(OPENSSL) req -new -nodes -key legitimate-ca-key.pem -out legitimate-csr.csr -subj "/C=GB/ST=Test State/L=Test City/O=Test Organisation/OU=Test Organisational Unit/CN=Test Common Name/UID=VGVzdFdpcmVHdWFyZFB1YmxpY0tleUxpdGVyYWxTdHI\="

wireguard-privkey.key:
	wg genkey > $@

wireguard-pubkey.key: wireguard-privkey.key
	wg pubkey < $< > $@

%-key.pem:
	$(OPENSSL) genrsa 2048 > $@
