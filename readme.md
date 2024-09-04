# Java partial implementation of CryptoJS
Provided encrypt and decrypt methods for replace next methods of CryptoJS:

### 1. encrypt
javascript
```javascript
CryptoJS.AES.encrypt(content, password).toString()
```
=>

java
```java
CryptoJSImpl.encrypt(dataToEncrypt, password);
```
### 2. decrypt
javascript
```javascript
CryptoJS.AES.decrypt(content, password).toString(CryptoJS.enc.Utf8)
```
=>

java
```java
CryptoJSImpl.decrypt(dataToDecrypt, password);
```

Credits:
- https://stackoverflow.com/questions/69094658/how-to-implement-cryptojs-aes-encrypt-function-in-java
- https://github.com/brix/crypto-js/issues/135