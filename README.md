# Cryptokis' Multiplexer
Multiplex several Cryptoki Libraries (PKCS #11 programming interface of various cryptographic tokens)

# Why is it useful ?
Usually each cryptographic token comes with a Cryptoki library and user may need to use multiple tokens simultaneously. This is a dead end for some applications which don't support loading multiple Cryptoki libraries and user does not have access to the software source code to add this capability.
It has to be mentioned that developing such a feature in most programming languages and the frameworks is not easy, even you have the source code.
