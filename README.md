# Cryptokis' Multiplexer
Multiplex several Cryptoki Libraries (PKCS #11 programming interface of various cryptographic tokens)

# Why is it useful ?
Usually each cryptographic token comes with a Cryptoki library and user may need to use multiple tokens simultaneously. This is a dead end for some applications which don't support loading multiple Cryptoki libraries and user does not have access to the software source code to add this capability.

It has to be mentioned that developing such a feature in most programming languages and the frameworks is not easy, even if you have the source code.

# Who should use it ?
- Cryptographic tokens producers can use it instead of make their global Cryptki heavy. This means that each product can have its own Cryptoki and the global Cryptoki which supports all or many tokens can be the Cryptokis's Multiplexer.

- Users who want to use multiple tokens in the applications with PKCS #11 support, such as FreeOTFE, OpenDNSSEC, OpenSSL, GnuTLS, OpenVPN, OpenSC, StrongSwan, TrueCrypt, OpenSSH, XCA, SecureCRT and many webservers which support Cryptoki for acceleration and protecting the private keys.

- Software developers who want to log all the PKCS #11 functions' parameters or want to use the PKCS #11 wrappers which usually support just one Cryptoki.

