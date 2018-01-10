### Example encoding decoding with PKCS#7 (CMS) Signature in Java (using command line tool - java, javac)

*How To Run*

- Clone this repo
- Compile and run in terminal with java
```
  javac -cp "lib/*" PKCS7Signer.java
  java -cp ".:lib/*" PKCS7Signer
```

*Keystore file keys*

  PATH_TO_KEYSTORE  = "pkcs7.keystore"
  KEY_ALIAS_IN_KEYSTORE = "pkcs7-key-alias"  
  KEYSTORE_PASSWORD = "pkcs7-password"



To generate a new keystore:
```
  keytool -genkey -v -keystore pkcs7.keystore -alias pkcs7-key-alias -keyalg RSA -keysize 2048 -validity 10000
```



-------------------------

To generate a crt file and private key: (not use in this example)
```
  sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout selfsigned.key -out selfsigned.crt
```

To generate a pem file: (not use in this example)
```
  sudo openssl dhparam -out dhparam.pem 2048
```
