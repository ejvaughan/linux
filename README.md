# Final Project #

Samuel Frank (sjfrank@wustl.edu), Ethan Vaughan (ejvaughan@wustl.edu),
Erik Wijmans (erikwijmans@wustl.edu)

For the full writeup, please see `writeup.pdf`. The following contains building
and testing instructions.

# How to build and test this kernel modification #

## Step 1. Generate a public/private key pair and X.509 certificate. ##

The certificate that is generated will be added to the system keyring when the
kernel is built. At runtime, any binary that is signed with the private key will
be successfully verified upon exec.

For example, the following command will generate a 4096-bit RSA public/private
key pair and self-signed certificate:

`openssl req -x509 -newkey rsa:4096 -keyout privatekey.pem -out certificate.pem -days 365`

We have provided our certificate and key, `cert.pem` and `privatekey.pem`, for
ease. The password for privatekey.pem is `crypto`.

## Step 2. Codesign all the binaries on the filesystem. ##

Mount the filesystem on a separate Linux machine, and then cd into the Pi's root directory.

Sign all the binaries on the Pi using the following invocation:

`sudo find . -print -type f -executable | xargs -I {} -P 8 sudo python3 /path/to/signer.py {} /path/to/certificate.pem /path/to/privatekey.pem <private_key_password>`

## Step 3. Patch, Build, and Install the kernel. ##

Checkout the following version of the kernel sources: https://github.com/raspberrypi/linux/archive/raspberrypi-kernel_1.20160506-1.tar.gz

Apply the provided patch, `codesign.patch`.

After the patch is applied, the kernel must be built with the following configuration. 
Applying the patch will create a pre-made kernel configuration, which should be sufficient.
We also have a build script, `build.sh`, for use in cross compilation.

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

## Step 4. Boot the Pi, and observe the output of dmesg ##

If your Pi boots after performing steps 1-3, congratulations! You are running a fully codesigned Raspberry Pi!

Inspect the system log, and observe that the signatures of all the binaries on the system are being verified.

## Step 5. Build a test program and try to exec ##

Trying to exec a binary that does not have a signature will fail.
In the system log, you will see output like:

[ 3159.294237] Checking ./test for signature
[ 3159.294259] No signature present for ./test!

## Step 6. Sign the test program and successfully exec it ##

Sign your test program with the included script, signer.py, as follows:

`./signer.py <path to binary> <path to certificate> <path to private key> <private key password>`

Now, when you try to execute the program, it will succeed. If you then inspect the system log,
you will see output similar to the following:

    [ 3445.119975] RSA: ==> RSA_verify_signature()
    [ 3445.119984] RSA: step 1: k=4096 size(S)=4095
    [ 3445.130176] RSA: size(x)=4081 xLen*8=4096
    [ 3445.130191] RSA: ==> RSA_verify(,,512,32,19)
    [ 3445.130203] RSA: <== RSA_verify() = 0
    [ 3445.130213] RSA: <== RSA_verify_signature() = 0
    [ 3445.130222] SIG: <==verify_signature() = 0
    [ 3445.130231] PKCS7: <== pkcs7_validate_trust_one() = 0
    [ 3445.130259] Signature successfully verified for ./test!

The presence of the "Signature successfully verified" message indicates that the
 binary was successfully verified.

If you subsequently modify the binary (changing its hash) and try to exec again,
 the binary will not run. Instead, you will see the following output in the
 system log:

    [ 3617.794701] RSA: <== RSA_verify() = -EKEYREJECTED [EM[T] hash mismatch]
    [ 3617.794713] RSA: <== RSA_verify_signature() = -129
    [ 3617.794723] PKCS7: <== pkcs7_verify() = -129
    [ 3617.794750] Signature verification failed for ./test!

This indicates that the check of the binary's signature failed, as expected.

Additionally, if you sign a binary with a private key whose certificate is not
in the system keyring, the binary will fail to exec. You will see the following
output:

	[ 6122.767192] X.509: Request for key 'ex:008a587a158d6c10e3310b30090603550406130255533112301006035504080c094572696b546f706961310f300d06035504070c065374756666733121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643111300f06092a864886f70d01090116026e6f' err -11
	[ 6122.767204] PKCS7: <== pkcs7_validate_trust_one() = -ENOKEY [cached]

This indicates that the binary was signed with a certificate that we do not trust.

## Miscellaneous ##

Our actual fork of the Linux kernel is located [here](https://github.com/ejvaughan/linux/tree/codesign)

Our scripts are located [here](https://github.com/baka-rust/sign)
