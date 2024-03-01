## Image Signing

The main purpose of image signing is to enable customers to be
able to trust enclave images which are signed by a certain
developer. This method simplifies the enclave update process.
Customers will have to allow signing certificates, instead
of specific image versions for their enclaves.

### How to Build a Signed Enclave Image

You can easily build a signed enclave image using Nitro CLI.
You will only need your signing certificate and your private
key in PEM format. If you don't have such a pair, you can
generate one using `openssl`.

```
$ nitro-cli build-enclave --docker-uri hello-world:latest  --output-file signed-hello-world.eif --signing-certificate certificate.pem --private-key key.pem
Start building the Enclave Image...
Enclave Image successfully created.
{
	"Measurements": {
		"HashAlgorithm": "Sha384 { ... }",
		"PCR0": "55c0acc442fd815e161f100c45810298f5c37ce9f61b675e4f8ba82e32b9bab3b674a6ef557eaa7db7577221683bbe9f",
		"PCR1": "aca6e62ffbf5f7deccac452d7f8cee1b94048faf62afc16c8ab68c9fed8c38010c73a669f9a36e596032f0b973d21895",
		"PCR2": "41e46bdda449ee3fd792772e5b766cb090d2a4a1b0e5a0c5e52c84d426c76cfd298ea725500a107e71399697df2ae2eb",
		"PCR8": "70da58334a884328944cd806127c7784677ab60a154249fd21546a217299ccfa1ebfe4fa96a163bf41d3bcfaebe68f6f"
	}
}
```

The output will include the value of PCR8, which is the SHA384
hash of the signing certificate's fingerprint. You can use
this value in your attestation-based customer master key (CMK)
policies. Doing this, ensures that only enclaves signed by a
particular key will have access to specific secret material.

### Algorithm

A signed enclave image includes an extra section - the signature
section. It contains an array of PCR Signatures. For the current
enclave image format (EIF v3) this array has only one element -
PCR0's signature. The value of PCR0 is the SHA384 hash of
the entire enclave image, without the signature section (for
signed images).

The PCR Signature contains the PEM-formatted signing certificate
and the serialized `COSESign1` object generated using the byte array
formed from the PCR's index and its value as payload and the
private key as signing key. The implementation of `COSESign1`
and more details can be found in the following crate:
[aws-nitro-enclaves-cose](https://github.com/awslabs/aws-nitro-enclaves-cose).

### How to Verify the Signature

1. Get the signature section from the enclave image. The `EifHeader`
contains an array with section offsets and each `EifSectionHeader`
contains an `EifSectionType`. You can find more details about these
headers in the [eif-defs](https://github.com/aws/aws-nitro-enclaves-image-format/) crate.

2. For each PCR Signature use the public key from the signing
certificate to verify the payload from the `COSESign1` object
(this can be done using the following crate:
[aws-nitro-enclaves-cose](https://github.com/awslabs/aws-nitro-enclaves-cose))
and check that the PCR's value is the same as the one computed by
Nitro CLI.
