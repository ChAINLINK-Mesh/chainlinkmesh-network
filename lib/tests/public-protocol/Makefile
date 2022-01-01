TARGETS = legitimate-packet.data legitimate-psk.data legitimate-psk.sha256 legitimate-psk-signature.sha256

all: $(TARGETS)

%.data: %.protodata
	pd $< -o $@

.PHONY: clean

clean:
	rm $(TARGETS)

legitimate-psk.sha256: legitimate-psk.data
	openssl dgst -sha256 -binary -out $@ $<

legitimate-psk-signature.sha256: legitimate-psk.data legitimate-ca-key.pem
	openssl dgst -sha256 -binary -sign legitimate-ca-key.pem -out $@ < $<

legitimate-packet.data: legitimate-packet.protodata legitimate-psk-signature.sha256
	pd $< -o $@
