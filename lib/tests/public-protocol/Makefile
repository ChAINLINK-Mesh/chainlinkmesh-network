TARGETS = legitimate-packet.data legitimate-psk.data legitimate-psk.sha256 legitimate-psk-signature.sha256 invalid-psk.data invalid-psk-packet.data

all: $(TARGETS)

%.data: %.protodata
	pd $< -o $@

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
