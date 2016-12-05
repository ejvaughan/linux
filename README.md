# How to test this kernel modification #

## Step 1. Generate a public/private key pair and X.509 certificate. ##

The certificate that is generated will be added to the system keyring when the kernel is built. At runtime, any binary that is signed with the private key will be successfully verified upon exec.

For example, the following command will generate a 4096-bit RSA public/private key pair and self-signed certificate:

`openssl req -x509 -newkey rsa:4096 -keyout privatekey.pem -out certificate.pem -days 365`

## Step 2. Build the kernel. ##

The kernel must be built with the following configuration:

    -*- Cryptographic API  --->

        <*> RSA algorithm

        -*- SHA1 digest algorithm
        {*} SHA224 and SHA256 algorithm
        <*> SHA384 and SHA512 digest algorithms

        -*- Asymmetric (public-key cryptographic) key type  --->

	    -*-   Asymmetric public-key crypto algorithm subtype
	    -*-   RSA public-key algorithm
	    -*-   X.509 certificate parser
	    -*-     PKCS#7 message parser

        Certificates for signature checking  --->

	    -*- Provide system-wide ring of trusted keys
	    (<filename of the certificate you generated in step 1>) Additional X.509 keys for default system keyring

    [*] Enable loadable module support  --->

        [*] Module signature verification

## Step 3. After installing the kernel, sign a binary with the signer.py script ##

At runtime, binaries that are signed will have their signatures checked when they are exec'd. So, to test this modification, you can sign a binary with your private key and then exec it.

The included script, signer.py, can sign a binary as follows:

`./signer.py <path to binary> <path to certificate> <path to private key> <private key password>`

## Step 4. Exec the signed binary and observe that its signature was verified by inspecting the output of the system log ##

Run your signed binary, and inspect the output of the system log via dmesg. You should see output similar to the following: 

	[ 4662.077632] SIG: ==>verify_signature()
	[ 4662.077641] RSA: ==> RSA_verify_signature()
	[ 4662.077652] RSA: step 1: k=4096 size(S)=4092
	[ 4662.088682] RSA: size(x)=4081 xLen*8=4096
	[ 4662.088702] RSA: ==> RSA_verify(,,512,32,19)
	[ 4662.088715] RSA: <== RSA_verify() = 0
	[ 4662.088726] RSA: <== RSA_verify_signature() = 0
	[ 4662.088735] SIG: <==verify_signature() = 0
	[ 4662.088745] PKCS7: <== pkcs7_validate_trust_one() = 0
	[ 4662.088761] Signature successfully verified for ./test!

The presence of the "Signature successfully verified" message indicates that the binary was successfully verified.

If you subsequently modify the binary (changing its hash) and try to exec again, the binary will not run. Instead, you will see the following output in the system log:

	[ 5659.002902] RSA: <== RSA_verify() = -EKEYREJECTED [EM[T] hash mismatch]
	[ 5659.002913] RSA: <== RSA_verify_signature() = -129
	[ 5659.002923] PKCS7: <== pkcs7_verify() = -129

This indicates that the check of the binary's signature failed, as expected.

Additionally, if you sign a binary with a private key whose certificate is not in the system keyring, the binary will fail to exec. You will see the following output:

	[ 6122.767192] X.509: Request for key 'ex:008a587a158d6c10e3310b30090603550406130255533112301006035504080c094572696b546f706961310f300d06035504070c065374756666733121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643111300f06092a864886f70d01090116026e6f' err -11
	[ 6122.767204] PKCS7: <== pkcs7_validate_trust_one() = -ENOKEY [cached]

This indicates that the binary was signed with a certificate that we do not trust.
