# SSL/TLS Vulnerability Cheat Sheet

## Vulnerable SSL/TLS Versions
|Issue|Severity|Attack pre-requisites|Impact|Description|References|
|-----|--------|---------------------|------|-----------|----------|
|SSLv2|Medium|MITM|Exposure and tampering in real-time|First released version of SSL that does not protect against MITM. Also susceptible to Bleichenbacher '98 (see BB98) attack to encrypt and decrypt data with server's RSA private key.||
|SSLv3|Low|BEASTly, CBC|Decryption of data|POODLE attack, allows decryption of data through a padding oracle attack. BEAST, allows decryption of data through a padding oracle attack. Requires BEASTly attack model.||
|TLSv1.0|Low|BEASTly, CBC|Decryption of data|see BEAST||
|DROWN|Medium|Adjacent network, RSA, key reuse across TLS versions|Decryption of data|BB98, as applied to SSLv2, to recover session keys encrypted with the server's RSA private key, can be used in conjunction with key reuse across different available versions of SSL/TLS to recover session keys from captured sessions and decrypt application data.|https://drownattack.com/|

## Vulnerable cipher suites
|Issue|Severity|Attack pre-requisites|Impact|Description|References|
|-----|--------|---------------------|------|-----------|----------|
|NULL|High|Adjacent network|Exposure and tampering in real-time|No encryption. Should only be enabled in testing. Disables encryption and integrity entirely.||
|EXPORT|High|Adjacent network|Exposure and tampering in real-time|Intentionally weakened ciphers that only provide 40 bits of security. With specialized hardware, real-time cracking may be possible, so long-lived sessions may be MITM'd invisibly. These ciphers are sometimes exploitable even if the client does not support or choose EXPORT-grade ciphers due to the nature of the algorithms themselves. (see FREAK, Logjam)|https://www.mitls.org/pages/attacks/SMACK#freak, https://weakdh.org/|
|DES|High|Adjacent network|Decryption of data, but not in real time.|Old cipher with small key size designed at a time when computing resources weren't enough to brute force DES keys efficiently. Can be brute forced in roughly a week with a machine costing $10,000.|http://www.sciengines.com/copacobana/|
|RC4|Low|BEASTly|Partial decryption of data.|Known serious biases in keystream output can be used to decrypt data, and given enough data, recover encryption keys. The IETF has prohibited the use of RC4 in any standards-compliant version of TLS, and Mozilla and Microsoft have recommended against any use of RC4.|https://en.wikipedia.org/wiki/RC4#Security|
|3DES/DES-CBC3/DES-EDE/Triple DES|Low|BEASTly, Old server version, Large amounts of data|Partial decryption of data.|Meet-in-the-middle attack reduces effective key strength to slightly above 112 bits. (see also SWEET32)|https://sweet32.info|
|Blowfish|Low|BEASTly, Old server version, CBC, Large amounts of data|Decryption of pseudo-random blocks of data.|See SWEET32.||
|MD5|Info|Theoretical|Tampering|MD5 has significant known collision weaknesses, with further advances HMAC-MD5 may be exploitable.|https://www.win.tue.nl/hashclash/|
|SHA-1 / SHA|Info|Theoretical|Tampering|SHA-1 has known collision weaknesses, with further advances HMAC-SHA may be exploitable.|https://shattered.io/|
|Anonymous DH/ECDH|Medium|MITM|Decryption and tampering in real time|Anonymous Diffie-Hellman and its elliptic curve variant is susceptible to a MITM attack that allows an attacker to establish an encrypted channel with both sides of the conversation and observe and modify traffic invisibly and in real time.||
|SWEET32|Low|BEASTly, Old server version, CBC, Large amounts of data|Decryption of pseudo-random blocks of data.|Random collisions in encrypted block values plus known plaintext for one of the two colliding blocks results in decryption of the other, requires hundreds of gigabytes of data for reasonable chance of success, plus large amounts of attacker-provided data.|https://sweet32.info/|


## Certificate issues
|Issue|Severity|Attack pre-requisites|Impact|Description|References|
|-----|--------|---------------------|------|-----------|----------|
|Self-signed certificate / Untrusted issuer|Medium|Client/user acceptance, MITM|Decryption and tampering in real-time|The certificate is not signed by an entity in any known trust store. There is no way to validate that the signing authority is valid. see User SSL/TLS Warnings.||
|Certificate subject mismatch|Medium|Client/user acceptance, MITM|Decryption and tampering in real-time|The certificate is not valid for the subject it is being used to protect. see User SSL/TLS Warnings.||
|Weak signature algorithm|Medium|Client/user acceptance, MITM|Decryption and tampering in real-time|The certificate uses a known weak signing algorithm such as MD5 or SHA-1 in its digital signature. Successful bait-and-switch attacks against signing authorities have been demonstrated to generate intermediate Certificate Authorities, compromising the chain of trust and therefore, all SSL/TLS traffic.|https://tools.ietf.org/id/draft-ietf-tls-md5-sha1-deprecate-00.html|
|Revoked certificate|Medium|Client/user acceptance, MITM|Decryption and tampering in real-time|A certificate in the chain of trust was revoked, and can no longer be trusted. see User SSL/TLS Warnings.||
|Debian faulty PRNG key|High|Adjacent network|Decryption and tampering in real-time|The key used in the certificate was generated with a version of Debian known to have serious vulnerabilities in its PRNG. Since only 65535 possible keys can be generated with such a PRNG, it is possible to keep a library of all possible key pairs, identify the key pair based on the server's presented public key, and decrypt and modify all traffic in real-time using the corresponding private key.|https://lists.debian.org/debian-security-announce/2008/msg00152.html|
|Expired certificate|Low|Client/user acceptance|Decryption and tampering in real-time|The certificate has passed its validity period and can no longer be trusted. Validity period for certificates attempt to limit the time attackers can spend trying to brute force a private key. see User SSL/TLS Warnings.||
|1024-bit RSA key|Low|Adjacent network, significant resources|Decryption and tampering in real-time|The certificate has a 1024-bit modulus. Given nation-state or organized crime level resources, a single 1024-bit public key could be factored to recover the private key in a short enough time to present a practical threat, as of this writing. Over time, as computing power grows, the feasibility of this attack will only grow.||
|768-bit or lower RSA key|High|Adjacent network|Decryption and tampering in real-time|The certificate has a 768-bit modulus, or smaller. This is small enough to allow an attacker to factor the modulus and recover the private key using off-the-shelf hardware for a modest price.||




## Implementation-specific vulnerabilities
|Issue|Severity|Attack pre-requisites|Impact|Description|References|
|-----|--------|---------------------|------|-----------|----------|
|HeartBleed|Critical|Old server version|Disclosure of server memory.|Exploits buffer overread in heartbeat TLS extension to read out server memory adjacent to buffer, often revealing request/response data or even private key material if server has just been restarted.|https://heartbleed.com/|
|Lucky 13|Low|BEASTly, Old server version, CBC|Partial decryption of data.|Exploits timing issue in MAC verification of certain vulnerable implementations to decrypt certain parts of encrypted data.||
|ROBOT|Medium|Old server version, Adjacent network, RSA|Encryption and decryption with server RSA private key|A small variation on Bleichenbacher's 1998 attack on RSA enables attacks on vulnerable TLS implementations. (see BB98)|https://robotattack.org/
|OpenSSL CCS Injection|Medium|Old server version, MITM|Decryption and tampering in real-time|The ChangeCipherSpec (CCS) message in the TLS handshake causes keys to be finalized. This should only occur once key material has been fully exchanged, but old versions of OpenSSL did not properly ensure this was the case. An attacker can cause keys to be generated using only public material by injecting CCS messages into TLS handshakes prematurely, then decrypt and modify traffic using the keys, which can be generated due to knowledge of the public key material used to generate them.|https://www.imperialviolet.org/2014/06/05/earlyccs.html|

## Configuration issues
|Issue|Severity|Attack pre-requisites|Impact|Description|References|
|-----|--------|---------------------|------|-----------|----------|
|CRIME|Medium|BEASTly, Old client version|Decryption of request data.|Compression oracle attack, applied to compressed and then encrypted HTTP requests where an attacker can obtain the encrypted data and measure its length. (see Compression Oracle)||
|TIME|Low|BEASTly, Old client version|Decryption of request data.|CRIME, but based on timing side channel. (see Compression Oracle, CRIME)||
|BREACH|Low|BEASTly, Old server version|Decryption of response data.|Compression oracle attack, applied to compressed and then encrypted HTTP responses. If an attacker using the BEASTly attack model against an application that reflects user input, the response data can be recovered. (see Compression Oracle)||
|No TLS_FALLBACK_SCSV|Low|MITM, other vulns|Downgrade|Newer versions of SSL/TLS prevent an attacker from modifying the list of supported algorithms being sent by the server and client to force the use of the weakest possible algorithm. However, without the TLS_FALLBACK_SCSV extension, an attacker can force a downgrade to the weakest version of SSL/TLS supported by the client and server.||
|Insecure renegotiation|Medium|MITM, Old server version, Old client version|Tampering.|An attacker can start a TLS session, sending some data, and then initiating a renegotiation when a client connects through a MITM channel to stitch the legitimate client into the connection, prepending arbitrary data to the request.||



# Definitions

* BB98 - Daniel Bleichenbacher presented an attack in 1998 on RSA with PKCS#1(v1.5) style padding, a padding scheme still commonly used, to decrypt and encrypt arbitrary data with the RSA private key, without actually gaining access to the private key itself, when a RSA-PKCS1 padding oracle is available. (see Padding Oracle)
* Padding Oracle - A system that accepts encrypted data from an attacker, decrypts it, and leaks information about whether the decrypted data has well-formed padding. Padding is junk data added to a message for various reasons.
* BEASTly - An attack model where an attacker can serve a Javascript file to a user that initiates many requests to the target application. This can be hosted from any origin. An attacker must also be able to observe the encrypted traffic, such as by presence on the same network as a victim.
* Compression Oracle - When compressing data that includes both secrets and adversary input before encrypting, an attacker can decrypt the unknown data. Most compression algorithms will de-duplicate strings that occur in multiple places in a piece of data, so an attacker can input different strings until the data compresses more efficiently, which can be observed when the encrypted data is smaller.
* User SSL/TLS Warnings - When a problem with an SSL/TLS certificate is encountered, browsers will present users with a warning. Users can choose to proceed anyway, despite security risks. If the normal usage of a website causes users to encounter these warnings, they may become accustomed to dismissing warnings when using the website without reading them. An attacker may be able to take advantage of this behavior as users may not notice when a MITM attack is occurring.

# Explanation of key strength in bits

No matter the algorithm, attackers will always be able to guess at the correct encryption key. If keys are chosen using a strong source of randomness as they should be, pulling off this attack should take longer to complete than the amount of time before the sun dies, or at least long enough that the gains from the attack should be useless once successful. The amount of time it takes to guess and check all possible keys is described here, assuming that a cracking machine exists that can perform one billion operations per second, which we'll just call Billy for fun. We can calculate the number of keys for an algorithm as 2<sup>bits of strength</sup>, then divide by one billion, giving us the number of seconds needed for Billy to try all keys.

|Bit strength|Difficulty|Real-world example|
|------------|----------|------------------|
|32|Billy tries all keys in four seconds.|A key was chosen poorly using only 32 effective bits of entropy|
|40|Billy tries all keys in 18 minutes.|Normal strength of EXPORT ciphers|
|56|Billy tries all keys in 13 days.|DES|
|64|Billy tries all keys in 9.7 years.|Maximum strength of EXPORT ciphers|
|112|One billion Billies working together (a giga-Billy) try all keys in 164.6 million years.|3DES, after applying Meet-in-the-Middle attack|
|128|One billion giga-Billies working together (an exa-Billy) try all keys in 10,790 years.|AES-128|
|192|An exa-Billy tries all keys in 199 sextillion years.|AES-192, or the expected (but not actual) strength of 3DES|
|256|An exa-exa-Billy (one billion billion exa-Billies) tries all keys in 3.7 septillion years.|AES-256|
