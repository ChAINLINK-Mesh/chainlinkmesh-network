TARGETS = legitimate-ca-pubkey.pem legitimate-packet.data legitimate-psk.data legitimate-psk.sha256 legitimate-psk-signature.sha256 invalid-psk.data invalid-psk-packet.data invalid-psk-signature.sha256 invalid-psk-signature-packet.data invalid-ca-key.pem unknown-referring-node.data legitimate-csr.csr wireguard-privkey.key wireguard-pubkey.key

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

legitimate-packet.data: legitimate-packet.protodata legitimate-psk.sha256 legitimate-psk-signature.sha256 legitimate-csr.csr
	pd $< -o $@

invalid-psk.data: legitimate-psk.data
	tail -c -1 $< > $@
	head -c 1 $< >> $@

invalid-psk-packet.data: invalid-psk-packet.protodata invalid-psk.sha256
	pd $< -o $@

invalid-ca-key.pem:
	openssl genrsa -out $@ 2048

invalid-psk-signature.sha256: legitimate-psk.data invalid-ca-key.pem
	openssl dgst -sha256 -binary -sign invalid-ca-key.pem -out $@ < $<

invalid-psk-signature-packet.data: invalid-psk-signature-packet.protodata invalid-psk-signature.sha256
	pd $< -o $@

unknown-referring-node.data: unknown-referring-node.protodata legitimate-psk.sha256 legitimate-psk-signature.sha256 legitimate-csr.csr
	pd $< -o $@

legitimate-csr.csr: legitimate-csr-key.pem
	openssl req -new -nodes -key legitimate-csr-key.pem -out legitimate-csr.csr -subj "/C=UK/ST=Test State/L=Test City/O=Test Organisation/OU=Test Organisational Unit/CN=Test Common Name"

wireguard-privkey.key:
	wg genkey > $@

wireguard-pubkey.key: wireguard-privkey.key
	wg pubkey < $< > $@
