#!/bin/bash

# generate_ca $key_length $subject
generate_ca()
{
	openssl genrsa -out ./certs/ca_key.pem $1
	openssl req -x509 -new -key ./certs/ca_key.pem -sha256 -days 3650 -subj "/C=CN/CN=SWS2021-BEAST-$2/" -out ./certs/ca_cert.pem
}

# generate_entity $key_length $name $subject $san
generate_entity()
{
	openssl genrsa -out "./certs/$2_key.pem" $1 
	openssl req -new -sha256 \
		-key "./certs/$2_key.pem" \
		-subj "/C=CN/CN=SWS2021-BEAST-$3/" \
		-addext "subjectAltName = $4" \
		-addext "basicConstraints = CA:FALSE" \
		-addext "keyUsage = nonRepudiation, digitalSignature, keyEncipherment" \
		-out request.csr
	cat << EOF | sed s/%%SAN%%/"$4"/g > .request.ext
[request_ext]
basicConstraints=critical,CA:FALSE
keyUsage = critical,digitalSignature, keyEncipherment
subjectAltName = %%SAN%%
# extendedKeyUsage = 1.3.6.1.5.5.7.3.1
extendedKeyUsage = serverAuth, clientAuth
EOF
	openssl x509 -req \
		-in request.csr \
		-CAkey "./certs/ca_key.pem" \
		-CA "./certs/ca_cert.pem" \
		-CAcreateserial \
		-out "./certs/$2_cert.pem" \
		-days 365 \
		-sha256 \
		-extfile .request.ext \
		-extensions request_ext
rm request.csr
rm .request.ext
}

generate_ca 4096 "CA"
generate_entity 2048 "server" "SERVER" "DNS:beast-server.local"
