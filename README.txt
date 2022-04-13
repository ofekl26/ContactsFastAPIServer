openssl genrsa -out ca.key 2048

openssl req -new -x509 -days 365 -key ca.key -out ca.crt

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr

vim <vim name>

subjectAltName=IP:server-public-ip

openssl x509 -req -extfile <vim name> -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

openssl x509 -in server.crt -out cert.pem

