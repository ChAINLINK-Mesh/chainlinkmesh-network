TARGETS = legitimate-ca-pubkey.pem legitimate-packet.data legitimate-psk.data legitimate-psk.sha256 legitimate-psk-signature.sha256 invalid-psk.data invalid-psk-packet.data invalid-psk-signature.sha256 invalid-psk-signature-packet.data invalid-ca-key.pem unknown-referring-node.data

all: $(TARGETS)

%.data: %.protodata
	pd $< -o $@

%-pubkey.pem: %-key.pem
	openssl rsa -pubout -out $@ -in $<

%.sha256: %.data
	openssl dgst -sha256 -binary -out $@ $<

.PHONY: clean

clean:
	rm $(TARGETS)

legitimate-psk-signature.sha256: legitimate-psk.data legitimate-ca-key.pem
	openssl dgst -sha256 -binary -sign legitimate-ca-key.pem -out $@ < $<

legitimate-packet.data: legitimate-packet.protodata legitimate-psk.sha256 legitimate-psk-signature.sha256
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

unknown-referring-packet.data: unknown-referring-node.protodata legitimate-psk.sha256 legitimate-psk-signature.sha256 legitimate-csr.csr
	pd $< -o $@