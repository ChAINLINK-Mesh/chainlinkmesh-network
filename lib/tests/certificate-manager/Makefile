TARGETS = x509-csr.pem private-key.key

all: $(TARGETS)

.PHONY: clean
clean:
	rm -f $(TARGETS)

x509-csr.pem private-key.key &:
	openssl req -newkey rsa:2048 -nodes -keyout private-key.key -out x509-csr.pem -subj "/C=UK/ST=State/L=City/O=Organisation/OU=Organisational Unit/CN=Common Name"
