TARGETS = legitimate-init-packet.data legitimate-psk.data legitimate-psk.sha256 legitimate-psk-signature.sha256 legitimate-csr.csr wireguard-privkey.key wireguard-pubkey.key legitimate-ca-key.pem legitimate-ca-pubkey.pem

all: $(TARGETS)

%.data: %.protodata
	pd $< -o $@

%-pubkey.pem: %-key.pem
	openssl rsa -pubout -out $@ -in $<

%.sha256: %.data
	openssl dgst -sha256 -binary -out $@ $<

.PHONY: clean

clean:
	rm -f $(TARGETS)

legitimate-psk-signature.sha256: legitimate-psk.data legitimate-ca-key.pem
	openssl dgst -sha256 -binary -sign legitimate-ca-key.pem -out $@ < $<

legitimate-init-packet.data: legitimate-init-packet.protodata legitimate-psk.sha256 legitimate-psk-signature.sha256 legitimate-csr.csr
	pd $< -o $@

legitimate-csr.csr: legitimate-ca-key.pem
	openssl req -new -nodes -key legitimate-ca-key.pem -out legitimate-csr.csr -subj "/C=UK/ST=Test State/L=Test City/O=Test Organisation/OU=Test Organisational Unit/CN=Test Common Name"

wireguard-privkey.key:
	wg genkey > $@

wireguard-pubkey.key: wireguard-privkey.key
	wg pubkey < $< > $@

%-key.pem:
	openssl genrsa 2048 > $@
