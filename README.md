# Cryptokis' Multiplexer
Multiplex several Cryptoki Libraries (PKCS #11 programming interface of various cryptographic tokens)

# Why is it useful ?
Usually each cryptographic token comes with a Cryptoki library and user may need to use multiple tokens simultaneously. This is a dead end for some applications which don't support loading multiple Cryptoki libraries and user does not have access to the software source code to add this capability.

It has to be mentioned that developing such a feature in most programming languages and the frameworks is not easy, even if you have the source code.

# Who should use it ?
- Cryptographic tokens producers can use it instead of make their global Cryptki heavy. This means that each product can have its own Cryptoki and the global Cryptoki which supports all or many tokens can be the Cryptokis's Multiplexer.

- Users who want to use multiple tokens in the applications with PKCS #11 support, such as FreeOTFE, OpenDNSSEC, OpenSSL, GnuTLS, OpenVPN, OpenSC, StrongSwan, TrueCrypt, OpenSSH, XCA, SecureCRT and many webservers which support Cryptoki for acceleration and protecting the private keys.

- Software developers who want to log all the PKCS #11 functions' parameters or want to use the PKCS #11 wrappers which usually support just one Cryptoki.

# How to use it ?
It's really easy to use the Cryptokis' Multiplexer. Just put the configuration file in the same place with the Multiplexer Cryptoki. Please note that the configuration file name should be same as Cryptoki's file name, but with .cfg extension. You can find the sample configuration file in "bin" directory.

[Cryptoki]

FILE_PATH_0 = Cryptoki library 0 file path

...

FILE_PATH_N = Cryptoki library N file path


[Log]

ENABLE = true/false
- enable and disable the logging facility 

SEPARATE_FILES = true/false
- if you want to separate the log of each thread, enable this option with true

FILE_PATH = c:/temp/cryptoki.log
- the log file path

# Todo
While I've been adding blocking mode to C_WaitForSlotEvent, I just added the Ms Windows specific locks of critical sections to safe the threads, thus supporting Linux has lost. The future plan is refining the code to compile on Linux.

