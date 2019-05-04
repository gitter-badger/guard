@echo off
echo|set /p= "################################################################# "
echo|set /p= " Generating Guard Server TLS keypair (to expose guard over HTTPS) "
echo #################################################################
keytool -genkeypair -alias guard-tls-server -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore guard-tls-server.p12 -dname "CN=Guard server,OU=ITM,O=DEMKADA,L=Paris,ST=ILE DE FRANCE,C=FR" -validity 36000

echo|set /p= "################################################################# "
echo|set /p= " Generating Guard RSA 2048 Keypair for JOSE operations (Javascript Object SignIng and Encryption) "
echo #################################################################
keytool -genkeypair -alias guard-rsa-keypair -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore guard-crypto-keystore.p12 -dname "CN=Guard JOSE keypair,OU=ITM,O=DEMKADA,L=Paris,ST=ILE DE FRANCE,C=FR" -validity 36000

echo|set /p= "################################################################# "
echo|set /p= " Generating Guard AES 128 key for database pii primary key column encryption "
echo #########################################################################
keytool -genseckey -alias guard-aes-key-for-pk -keyalg AES -keysize 128 -storetype PKCS12 -keystore guard-crypto-keystore.p12

echo|set /p= "################################################################# "
echo|set /p= " Generating Guard AES 128 key for others database pii columns encryption "
echo #########################################################################
keytool -genseckey -alias guard-aes-key-for-data -keyalg AES -keysize 128 -storetype PKCS12 -keystore guard-crypto-keystore.p12