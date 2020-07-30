// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use openssl::bn::BigNum;
use openssl::ec::EcKeyRef;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{Private, Public};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_cbor::Error as CborError;
use serde_cbor::Value as CborValue;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HeaderMap(
    #[serde(deserialize_with = "::serde_with::rust::maps_duplicate_key_is_error::deserialize")]
    BTreeMap<CborValue, CborValue>,
);

impl HeaderMap {
    pub fn new() -> Self {
        HeaderMap(BTreeMap::new())
    }

    pub fn insert(&mut self, key: CborValue, value: CborValue) -> Option<CborValue> {
        self.0.insert(key, value)
    }

    pub fn get(&self, key: &CborValue) -> Option<&CborValue> {
        self.0.get(key)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn from_bytes(header_map: &[u8]) -> Result<Self, CborError> {
        serde_cbor::from_slice(&header_map)
    }
}

/// Values from https://tools.ietf.org/html/rfc8152#section-8.1
#[derive(Debug, Copy, Clone, Serialize_repr, Deserialize_repr)]
#[repr(i8)]
pub enum SignatureAlgorithm {
    ES256 = -7,  //  ECDSA w/ SHA-256
    ES384 = -35, //  ECDSA w/ SHA-384
    ES512 = -36, // ECDSA w/ SHA-512
}

impl Into<HeaderMap> for SignatureAlgorithm {
    fn into(self) -> HeaderMap {
        // Convenience method for creating the map that would go into the signature structures
        // Can be appended into a larger HeaderMap
        // `1` is the index defined in the spec for Algorithm
        let mut map = HeaderMap::new();
        map.insert(1.into(), (self as i8).into());
        map
    }
}

///  https://tools.ietf.org/html/rfc8152#section-4.4
///
///  In order to create a signature, a well-defined byte stream is needed.
///  The Sig_structure is used to create the canonical form.  This signing
///  and verification process takes in the body information (COSE_Sign or
///  COSE_Sign1), the signer information (COSE_Signature), and the
///  application data (external source).  A Sig_structure is a CBOR array.
///  The fields of the Sig_structure in order are:
///
///  1.  A text string identifying the context of the signature.  The
///      context string is:
///
///         "Signature" for signatures using the COSE_Signature structure.
///
///         "Signature1" for signatures using the COSE_Sign1 structure.
///
///         "CounterSignature" for signatures used as counter signature
///         attributes.
///
///  2.  The protected attributes from the body structure encoded in a
///      bstr type.  If there are no protected attributes, a bstr of
///      length zero is used.
///
///  3.  The protected attributes from the signer structure encoded in a
///      bstr type.  If there are no protected attributes, a bstr of
///      length zero is used.  This field is omitted for the COSE_Sign1
///      signature structure.
///
///  4.  The protected attributes from the application encoded in a bstr
///      type.  If this field is not supplied, it defaults to a zero-
///      length binary string.  (See Section 4.3 for application guidance
///      on constructing this field.)
///
///  5.  The payload to be signed encoded in a bstr type.  The payload is
///      placed here independent of how it is transported.
///
///  Note: A struct serializes to a map, while a tuple serializes to an array,
///  which is why this struct is actually a tuple
///  Note: This structure only needs to be serializable, since it's
///  used for generating a signature and not transported anywhere. Both
///  sides need to generate it independently.
#[derive(Debug, Clone, Serialize)]
pub struct SigStructure(
    /// context: "Signature" / "Signature1" / "CounterSignature"
    String,
    /// body_protected : empty_or_serialized_map,
    ByteBuf,
    /// ? sign_protected : empty_or_serialized_map,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    Option<ByteBuf>,
    /// external_aad : bstr,
    ByteBuf,
    /// payload : bstr
    ByteBuf,
);

fn map_to_empty_or_serialized(map: &HeaderMap) -> Result<Vec<u8>, CborError> {
    if map.is_empty() {
        Ok(vec![])
    } else {
        Ok(serde_cbor::to_vec(map)?)
    }
}

impl SigStructure {
    /// Takes the protected field of the COSE_Sign object and a raw slice of bytes as payload and creates a
    /// SigStructure for one signer from it
    pub fn new_sign1(body_protected: &[u8], payload: &[u8]) -> Result<Self, CborError> {
        Ok(SigStructure(
            String::from("Signature1"),
            ByteBuf::from(body_protected.to_vec()),
            None,
            ByteBuf::new(),
            ByteBuf::from(payload.to_vec()),
        ))
    }

    /// Takes the protected field of the COSE_Sign object and a CborValue as payload and creates a
    /// SigStructure for one signer from it
    pub fn new_sign1_cbor_value(
        body_protected: &[u8],
        payload: &CborValue,
    ) -> Result<Self, CborError> {
        Self::new_sign1(body_protected, &serde_cbor::to_vec(payload)?)
    }

    /// Serializes the SigStructure to . We don't care about deserialization, since
    /// both sides are supposed to compute the SigStructure and compare.
    pub fn as_bytes(&self) -> Result<Vec<u8>, CborError> {
        serde_cbor::to_vec(self)
    }
}

///  https://tools.ietf.org/html/rfc8152#section-4.2.
///
///  The COSE_Sign1 signature structure is used when only one signature is
///  going to be placed on a message.  The parameters dealing with the
///  content and the signature are placed in the same pair of buckets
///  rather than having the separation of COSE_Sign.
///
///  The structure can be encoded as either tagged or untagged depending
///  on the context it will be used in.  A tagged COSE_Sign1 structure is
///  identified by the CBOR tag 18.  The CDDL fragment that represents
///  this is:
///
///  COSE_Sign1_Tagged = #6.18(COSE_Sign1)
///
///  The CBOR object that carries the body, the signature, and the
///  information about the body and signature is called the COSE_Sign1
///  structure.  Examples of COSE_Sign1 messages can be found in
///  Appendix C.2.
///
///  The COSE_Sign1 structure is a CBOR array.  The fields of the array in
///  order are:
///
///  protected:  This is as described in Section 3.
///
///  unprotected:  This is as described in Section 3.
///
///  payload:  This is as described in Section 4.1.
///
///  signature:  This field contains the computed signature value.  The
///     type of the field is a bstr.
///
///  The CDDL fragment that represents the above text for COSE_Sign1
///  follows.
///
///  COSE_Sign1 = [
///      Headers,
///      payload : bstr / nil,
///      signature : bstr
///  ]
///
///  # https://tools.ietf.org/html/rfc8152#section-3
///
///  Headers = (
///       protected : empty_or_serialized_map,
///       unprotected : header_map
///   )
///
///   header_map = {
///       Generic_Headers,
///       * label => values
///   }
///
///   empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
///
///   Generic_Headers = (
///       ? 1 => int / tstr,  ; algorithm identifier
///       ? 2 => [+label],    ; criticality
///       ? 3 => tstr / int,  ; content type
///       ? 4 => bstr,        ; key identifier
///       ? 5 => bstr,        ; IV
///       ? 6 => bstr,        ; Partial IV
///       ? 7 => COSE_Signature / [+COSE_Signature] ; Counter signature
///   )
///
///   Note: Currently, the structures are not tagged, since it isn't required by
///   the spec and the only way to achieve this is to add the token at the
///   start of the serialized object, since the serde_cbor library doesn't
///   support custom tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct COSESign1(
    /// protected: empty_or_serialized_map,
    ByteBuf,
    /// unprotected: HeaderMap
    HeaderMap,
    /// payload: bstr
    /// The spec allows payload to be nil and transported separately, but it's not useful at the
    /// moment, so this is just a ByteBuf for simplicity.
    ByteBuf,
    /// signature: bstr
    ByteBuf,
);

#[derive(Debug)]
pub enum COSEError {
    SignatureError(openssl::error::ErrorStack),
    UnimplementedError,
    UnsupportedError(String),
    UnverifiedSignature,
    SpecificationError(String),
    SerializationError(CborError),
}

impl COSESign1 {
    /// Follows the recommandations put in place by the RFC and doesn't deal with potential
    /// mismatches: https://tools.ietf.org/html/rfc8152#section-8.1.
    fn curve_to_parameters(
        curve_name: Nid,
    ) -> Result<(SignatureAlgorithm, MessageDigest, usize), COSEError> {
        match curve_name {
            // Recommended to use with SHA256
            Nid::X9_62_PRIME256V1 => Ok((SignatureAlgorithm::ES256, MessageDigest::sha256(), 32)),
            // Recommended to use with SHA384
            Nid::SECP384R1 => Ok((SignatureAlgorithm::ES384, MessageDigest::sha384(), 48)),
            // Recommended to use with SHA512
            Nid::SECP521R1 => Ok((
                SignatureAlgorithm::ES512,
                MessageDigest::sha512(),
                66, /* Not a typo */
            )),
            _ => Err(COSEError::UnsupportedError(format!(
                "Curve name {:?} is not supported",
                curve_name
            ))),
        }
    }

    /// Creates a COSESign1 structure from the given payload and some unprotected data in the form
    /// of a HeaderMap. Signs the content with the given key using the recommedations from the spec
    /// and sets the protected part of the document to reflect the algorithm used.
    pub fn new(
        payload: &[u8],
        unprotected: &HeaderMap,
        key: &EcKeyRef<Private>,
    ) -> Result<Self, COSEError> {
        let curve_name = key
            .group()
            .curve_name()
            .ok_or(COSEError::UnimplementedError)?;

        let (sig_alg, digest, key_length) = COSESign1::curve_to_parameters(curve_name)?;

        // Create the SigStruct to sign
        let protected: HeaderMap = sig_alg.into();
        let protected_bytes =
            map_to_empty_or_serialized(&protected).map_err(COSEError::SerializationError)?;

        let sig_structure = SigStructure::new_sign1(&protected_bytes, payload)
            .map_err(COSEError::SerializationError)?;

        let struct_digest = hash(
            digest,
            &sig_structure
                .as_bytes()
                .map_err(COSEError::SerializationError)?,
        )
        .map_err(COSEError::SignatureError)?;

        // The spec defines the signature as:
        // Signature = I2OSP(R, n) | I2OSP(S, n), where n = ceiling(key_length / 8)
        // The Signer interface doesn't provide this, so this will use EcdsaSig interface instead
        // and concatenate R and S.
        // See https://tools.ietf.org/html/rfc8017#section-4.1 for details.
        let signature =
            EcdsaSig::sign(struct_digest.as_ref(), &key).map_err(COSEError::SignatureError)?;
        let bytes_r = signature.r().to_vec();
        let bytes_s = signature.s().to_vec();

        // These should *never* exceed ceiling(key_length / 8)
        assert!(bytes_r.len() <= key_length);
        assert!(bytes_s.len() <= key_length);

        let mut signature_bytes = vec![0u8; key_length * 2];

        // This is big-endian encoding so padding might be added at the start if the factor is
        // too short.
        let offset_copy = key_length - bytes_r.len();
        signature_bytes[offset_copy..offset_copy + bytes_r.len()].copy_from_slice(&bytes_r);

        // This is big-endian encoding so padding might be added at the start if the factor is
        // too short.
        let offset_copy = key_length - bytes_s.len() + key_length;
        signature_bytes[offset_copy..offset_copy + bytes_s.len()].copy_from_slice(&bytes_s);

        Ok(COSESign1(
            ByteBuf::from(protected_bytes),
            unprotected.clone(),
            ByteBuf::from(payload.to_vec()),
            ByteBuf::from(signature_bytes),
        ))
    }

    /// Serializes the structure for transport / storage. `tagged` is currently unused, but it
    /// will be used to set the #6.18 tag on the object as allowed by the spec.
    pub fn as_bytes(&self, _tagged: bool) -> Result<Vec<u8>, COSEError> {
        let bytes = serde_cbor::to_vec(&self).map_err(COSEError::SerializationError)?;
        Ok(bytes)
    }

    /// This function deserializes the structure, but doesn't check the contents for correctness
    /// at all.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, COSEError> {
        let cosesign1: Self =
            serde_cbor::from_slice(bytes).map_err(COSEError::SerializationError)?;

        let protected = cosesign1.0.as_slice();
        let _: HeaderMap =
            serde_cbor::from_slice(protected).map_err(COSEError::SerializationError)?;
        Ok(cosesign1)
    }

    /// This checks the signature included in the structure against the given public key and
    /// returns true if the signature matches the given key.
    pub fn verify_signature(&self, key: &EcKeyRef<Public>) -> Result<bool, COSEError> {
        // Don't support anonymous curves
        let curve_name = key.group().curve_name().ok_or_else(|| {
            COSEError::UnsupportedError("Anonymous curves are not supported".to_string())
        })?;

        // In theory, the digest itself does not have to match the curve, however,
        // this is the recommendation and the spec does not even provide a way to specify
        // another digest type, so, signatures will fail if this is done differently
        let (signature_alg, digest, key_length) = COSESign1::curve_to_parameters(curve_name)?;

        // The spec reads as follows:
        //    alg:  This parameter is used to indicate the algorithm used for the
        //        security processing.  This parameter MUST be authenticated where
        //        the ability to do so exists.  This support is provided by AEAD
        //        algorithms or construction (COSE_Sign, COSE_Sign0, COSE_Mac, and
        //        COSE_Mac0).  This authentication can be done either by placing the
        //        header in the protected header bucket or as part of the externally
        //        supplied data.  The value is taken from the "COSE Algorithms"
        //        registry (see Section 16.4).
        // TODO: Currently this only validates the case where the Signature Algorithm is included
        // in the protected headers. To be compatible with other implementations this should be
        // more flexible, as stated in the spec.
        let protected: HeaderMap =
            HeaderMap::from_bytes(&self.0).map_err(COSEError::SerializationError)?;

        if let Some(protected_signature_alg_val) = protected.get(&CborValue::Integer(1)) {
            let protected_signature_alg = match protected_signature_alg_val {
                CborValue::Integer(val) => val,
                _ => {
                    return Err(COSEError::SpecificationError(
                        "Protected Header contains invalid Signature Algorithm specification"
                            .to_string(),
                    ))
                }
            };
            if protected_signature_alg != &(signature_alg as i8 as i128) {
                // The key doesn't match the one specified in the HeaderMap, so this fails
                // signature verification immediately.
                return Ok(false);
            }
        } else {
            return Err(COSEError::SpecificationError(
                "Protected Header does not contain a valid Signature Algorithm specification"
                    .to_string(),
            ));
        }

        let sig_structure = SigStructure::new_sign1(
            &self.0, /* protected headers */
            &self.2, /* payload */
        )
        .map_err(COSEError::SerializationError)?;

        let struct_digest = hash(
            digest,
            &sig_structure
                .as_bytes()
                .map_err(COSEError::SerializationError)?,
        )
        .map_err(COSEError::SignatureError)?;

        // Recover the R and S factors from the signature contained in the object
        let (bytes_r, bytes_s) = self.3.split_at(key_length);

        let r = BigNum::from_slice(&bytes_r).map_err(COSEError::SignatureError)?;
        let s = BigNum::from_slice(&bytes_s).map_err(COSEError::SignatureError)?;

        let sig = EcdsaSig::from_private_components(r, s).map_err(COSEError::SignatureError)?;
        Ok(sig
            .verify(&struct_digest, &key)
            .map_err(COSEError::SignatureError)?)
    }

    /// This gets the `payload` of the document. If `key` is provided, it only gets the payload
    /// if the signature is correctly verified, otherwise returns
    /// `Err(COSEError::UnverifiedSignature)`.
    pub fn get_payload(&self, key: Option<&EcKeyRef<Public>>) -> Result<Vec<u8>, COSEError> {
        if key.is_some() && !self.verify_signature(key.unwrap())? {
            return Err(COSEError::UnverifiedSignature);
        }
        Ok(self.2.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::EcKey;

    // Public domain work: Pride and Prejudice by Jane Austen, taken from https://www.gutenberg.org/files/1342/1342.txt
    const TEXT: &[u8] = b"It is a truth universally acknowledged, that a single man in possession of a good fortune, must be in want of a wife.";

    #[test]
    fn map_serialization() {
        // Empty map
        let map: HeaderMap = HeaderMap::new();
        assert_eq!(map_to_empty_or_serialized(&map).unwrap(), []);

        // Checks that the body_protected field will be serialized correctly
        let map: HeaderMap = SignatureAlgorithm::ES256.into();
        assert_eq!(
            map_to_empty_or_serialized(&map).unwrap(),
            [0xa1, 0x01, 0x26]
        );

        let map: HeaderMap = SignatureAlgorithm::ES384.into();
        assert_eq!(
            map_to_empty_or_serialized(&map).unwrap(),
            [0xa1, 0x01, 0x38, 0x22]
        );

        let map: HeaderMap = SignatureAlgorithm::ES512.into();
        assert_eq!(
            map_to_empty_or_serialized(&map).unwrap(),
            [0xa1, 0x01, 0x38, 0x23]
        );
    }

    #[test]
    fn map_with_duplicates() {
        // Check that HeaderMaps with duplicate entries emit error
        // {1: 42, 2: 42}
        let test = [0xa2, 0x01, 0x18, 0x2A, 0x02, 0x18, 0x2A];
        let map: HeaderMap = serde_cbor::from_slice(&test).unwrap();
        assert_eq!(
            map.get(&CborValue::Integer(1)),
            Some(&CborValue::Integer(42))
        );
        assert_eq!(
            map.get(&CborValue::Integer(2)),
            Some(&CborValue::Integer(42))
        );

        // {1: 42, 2: 42, 1: 43}
        let test = [0xa3, 0x01, 0x18, 0x2A, 0x02, 0x18, 0x2A, 0x01, 0x18, 0x2B];
        let map: Result<HeaderMap, _> = serde_cbor::from_slice(&test);
        assert!(map.is_err());

        // {1: 42, 2: 42, 2: 42}
        let test = [0xa3, 0x01, 0x18, 0x2A, 0x02, 0x18, 0x2A, 0x02, 0x18, 0x2A];
        let map: Result<HeaderMap, _> = serde_cbor::from_slice(&test);
        assert!(map.is_err());
    }

    #[test]
    fn sig_structure_text() {
        let map = HeaderMap::new();

        let map_serialized = map_to_empty_or_serialized(&map).unwrap();
        let sig_structure = SigStructure::new_sign1(&map_serialized, TEXT).unwrap();

        assert_eq!(
            vec![
                0x84, /* "Signature1" */
                0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
                /* protected: */
                0x40, /* unprotected: */
                0x40, /* payload: */
                0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
                0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
                0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
                0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
                0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
                0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
                0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
                0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
                0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E,
            ],
            sig_structure.as_bytes().unwrap()
        );

        let map: HeaderMap = SignatureAlgorithm::ES256.into();
        let map_serialized = map_to_empty_or_serialized(&map).unwrap();
        let sig_structure = SigStructure::new_sign1(&map_serialized, TEXT).unwrap();
        assert_eq!(
            vec![
                0x84, /* "Signature1" */
                0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
                /* protected: */
                0x43, 0xA1, 0x01, 0x26, /* unprotected: */
                0x40, /* payload: */
                0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
                0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
                0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
                0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
                0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
                0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
                0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
                0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
                0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E,
            ],
            sig_structure.as_bytes().unwrap()
        );
    }

    /// Static PRIME256V1/P-256 key to be used when cross-validating the implementation
    fn get_ec256_test_key() -> (EcKey<Private>, EcKey<Public>) {
        let alg =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let x = openssl::bn::BigNum::from_hex_str(
            "9ff7423a1aace5f3e33dfaeda2c7744e3d15c2a4f6382386c93fa60c1bdb260c",
        )
        .unwrap();
        let y = openssl::bn::BigNum::from_hex_str(
            "3489e6b132f36e5ece948e73bd44231a1c3d0dacf566712a44fe8a9835d5b6fe",
        )
        .unwrap();
        let d = openssl::bn::BigNum::from_hex_str(
            "8e21d79fb6955dbe7bb592d92de4690f8bf75dc1495b2433ba78d5828e1f933f",
        )
        .unwrap();

        let ec_public =
            openssl::ec::EcKey::from_public_key_affine_coordinates(&alg, &x, &y).unwrap();
        let ec_private =
            openssl::ec::EcKey::from_private_components(&alg, &d, &ec_public.public_key()).unwrap();
        (ec_private, ec_public)
    }

    /// Static SECP384R1/P-384 key to be used when cross-validating the implementation
    fn get_ec384_test_key() -> (EcKey<Private>, EcKey<Public>) {
        let alg = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
        let x = openssl::bn::BigNum::from_hex_str(
            "5a829f62f2f4f095c0e922719285b4b981c677912870a413137a5d7319916fa8\
             584a6036951d06ffeae99ca73ab1a2dc",
        )
        .unwrap();
        let y = openssl::bn::BigNum::from_hex_str(
            "e1b76e08cb20d6afcea7423f8b49ec841dde6f210a6174750bf8136a31549422\
             4df153184557a6c29a1d7994804f604c",
        )
        .unwrap();
        let d = openssl::bn::BigNum::from_hex_str(
            "55c6aa815a31741bc37f0ffddea73af2397bad640816ef22bfb689efc1b6cc68\
             2a73f7e5a657248e3abad500e46d5afc",
        )
        .unwrap();
        let ec_public =
            openssl::ec::EcKey::from_public_key_affine_coordinates(&alg, &x, &y).unwrap();
        let ec_private =
            openssl::ec::EcKey::from_private_components(&alg, &d, &ec_public.public_key()).unwrap();
        (ec_private, ec_public)
    }

    /// Static SECP521R1/P-512 key to be used when cross-validating the implementation
    fn get_ec512_test_key() -> (EcKey<Private>, EcKey<Public>) {
        let alg = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP521R1).unwrap();
        let x = openssl::bn::BigNum::from_hex_str(
            "004365ee31a93b6e69b2c895890aaae14194cd84601bbb59587ad08ab5960522\
             7dc7b34288e6471b0f06050763b88b4fb017f279c86030b0069100401e4016a3\
             be8a",
        )
        .unwrap();
        let y = openssl::bn::BigNum::from_hex_str(
            "00792d772bf93cd965027df2df02d3f99ea1c4ecd18c20738ebae66854fd3afc\
             d2ea4e902bcd37a4d2a5c639caee71513acaf7d8f7ffa11042257c5d8c697409\
             5713",
        )
        .unwrap();
        let d = openssl::bn::BigNum::from_hex_str(
            "007c6fd88271bcd6c5d6bada258691a27700abeff0ad86891a27f93a73f00947\
             7c53b4e069db544429ad8220d18813f5f3ab90946ebdf4f41ca929999709f7c4\
             89e8",
        )
        .unwrap();
        let ec_public =
            openssl::ec::EcKey::from_public_key_affine_coordinates(&alg, &x, &y).unwrap();
        let ec_private =
            openssl::ec::EcKey::from_private_components(&alg, &d, &ec_public.public_key()).unwrap();
        (ec_private, ec_public)
    }

    /// Randomly generate PRIME256V1/P-256 key to use for validating signining internally
    fn generate_ec256_test_key() -> (EcKey<Private>, EcKey<Public>) {
        let alg =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let ec_private = openssl::ec::EcKey::generate(&alg).unwrap();
        let ec_public = openssl::ec::EcKey::from_public_key(&alg, ec_private.public_key()).unwrap();
        (ec_private, ec_public)
    }

    /// Randomly generate SECP384R1/P-384 key to use for validating signining internally
    fn generate_ec384_test_key() -> (EcKey<Private>, EcKey<Public>) {
        let alg = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
        let ec_private = openssl::ec::EcKey::generate(&alg).unwrap();
        let ec_public = openssl::ec::EcKey::from_public_key(&alg, ec_private.public_key()).unwrap();
        (ec_private, ec_public)
    }

    /// Randomly generate SECP521R1/P-512 key to use for validating signing internally
    fn generate_ec512_test_key() -> (EcKey<Private>, EcKey<Public>) {
        let alg = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP521R1).unwrap();
        let ec_private = openssl::ec::EcKey::generate(&alg).unwrap();
        let ec_public = openssl::ec::EcKey::from_public_key(&alg, ec_private.public_key()).unwrap();
        (ec_private, ec_public)
    }

    #[test]
    fn cose_sign1_ec256_validate() {
        let (_, ec_public) = get_ec256_test_key();

        // This output was validated against COSE-C implementation
        let cose_doc = COSESign1::from_bytes(&vec![
            0x84, /* Protected: {1: -7} */
            0x43, 0xA1, 0x01, 0x26, /* Unprotected: {4: '11'} */
            0xA1, 0x04, 0x42, 0x31, 0x31, /* payload: */
            0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
            0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
            0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
            0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
            0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
            0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
            0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
            0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
            0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E, /* Signature - length 32 x 2 */
            0x58, 0x40, /* R: */
            0x6E, 0x6D, 0xF6, 0x54, 0x89, 0xEA, 0x3B, 0x01, 0x88, 0x33, 0xF5, 0xFC, 0x4F, 0x84,
            0xF8, 0x1B, 0x4D, 0x5E, 0xFD, 0x5A, 0x09, 0xD5, 0xC6, 0x2F, 0x2E, 0x92, 0x38, 0x5D,
            0xCE, 0x31, 0xE2, 0xD1, /* S: */
            0x5A, 0x53, 0xA9, 0xF0, 0x75, 0xE8, 0xFB, 0x39, 0x66, 0x9F, 0xCD, 0x4E, 0xB5, 0x22,
            0xC8, 0x5C, 0x92, 0x77, 0x45, 0x2F, 0xA8, 0x57, 0xF5, 0xFE, 0x37, 0x9E, 0xDD, 0xEF,
            0x0F, 0xAB, 0x3C, 0xDD,
        ])
        .unwrap();

        assert_eq!(cose_doc.get_payload(Some(&ec_public)).unwrap(), TEXT);
    }

    #[test]
    fn cose_sign1_ec384_validate() {
        let (_, ec_public) = get_ec384_test_key();

        // This output was validated against COSE-C implementation
        let cose_doc = COSESign1::from_bytes(&vec![
            0x84, /* Protected: {1: -35} */
            0x44, 0xA1, 0x01, 0x38, 0x22, /* Unprotected: {4: '11'} */
            0xA1, 0x04, 0x42, 0x31, 0x31, /* payload: */
            0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
            0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
            0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
            0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
            0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
            0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
            0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
            0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
            0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E, /* signature - length 48 x 2 */
            0x58, 0x60, /* R: */
            0xCD, 0x42, 0xD2, 0x76, 0x32, 0xD5, 0x41, 0x4E, 0x4B, 0x54, 0x5C, 0x95, 0xFD, 0xE6,
            0xE3, 0x50, 0x5B, 0x93, 0x58, 0x0F, 0x4B, 0x77, 0x31, 0xD1, 0x4A, 0x86, 0x52, 0x31,
            0x75, 0x26, 0x6C, 0xDE, 0xB2, 0x4A, 0xFF, 0x2D, 0xE3, 0x36, 0x4E, 0x9C, 0xEE, 0xE9,
            0xF9, 0xF7, 0x95, 0xA0, 0x15, 0x15, /* S: */
            0x5B, 0xC7, 0x12, 0xAA, 0x28, 0x63, 0xE2, 0xAA, 0xF6, 0x07, 0x8A, 0x81, 0x90, 0x93,
            0xFD, 0xFC, 0x70, 0x59, 0xA3, 0xF1, 0x46, 0x7F, 0x64, 0xEC, 0x7E, 0x22, 0x1F, 0xD1,
            0x63, 0xD8, 0x0B, 0x3B, 0x55, 0x26, 0x25, 0xCF, 0x37, 0x9D, 0x1C, 0xBB, 0x9E, 0x51,
            0x38, 0xCC, 0xD0, 0x7A, 0x19, 0x31,
        ])
        .unwrap();

        assert_eq!(cose_doc.get_payload(Some(&ec_public)).unwrap(), TEXT);
    }

    #[test]
    fn cose_sign1_ec512_validate() {
        let (_, ec_public) = get_ec512_test_key();

        // This output was validated against COSE-C implementation
        let cose_doc = COSESign1::from_bytes(&vec![
            0x84, /* Protected: {1: -36} */
            0x44, 0xA1, 0x01, 0x38, 0x23, /* Unprotected: {4: '11'} */
            0xA1, 0x04, 0x42, 0x31, 0x31, /* payload: */
            0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
            0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
            0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
            0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
            0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
            0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
            0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
            0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
            0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E, /* signature - length 66 x 2 */
            0x58, 0x84, /* R: */
            0x01, 0xE5, 0xAE, 0x6A, 0xE6, 0xE2, 0xE3, 0xC0, 0xB5, 0x1D, 0xD1, 0x62, 0x74, 0x1C,
            0xF9, 0x9D, 0xA6, 0x88, 0x19, 0x5C, 0xD9, 0x0E, 0x65, 0xFB, 0xBE, 0xE2, 0x38, 0x83,
            0x81, 0x32, 0x3C, 0xAE, 0xC9, 0x1B, 0x3D, 0x0E, 0x3A, 0xC1, 0x4D, 0x0B, 0x8B, 0x29,
            0xA8, 0x56, 0x2E, 0xB2, 0x17, 0x65, 0x9F, 0x27, 0xBE, 0xB4, 0x30, 0xA1, 0xD7, 0x4F,
            0x42, 0x35, 0x3A, 0x2C, 0x0A, 0xC5, 0x1F, 0xC2, 0x36, 0x48, /* S: */
            0x00, 0x00, 0x89, 0xEA, 0xF7, 0x09, 0x50, 0xF8, 0x45, 0x83, 0xA7, 0xC4, 0x79, 0x2F,
            0xAD, 0xC6, 0x96, 0xC3, 0x03, 0x33, 0xF2, 0xDF, 0x19, 0x48, 0x83, 0x93, 0xAB, 0xAE,
            0x31, 0x6A, 0x2E, 0x17, 0x1D, 0x58, 0x87, 0x65, 0xC4, 0x36, 0xA2, 0xA2, 0x05, 0xAD,
            0x81, 0x51, 0xF3, 0x97, 0x3E, 0xC0, 0xB4, 0xA7, 0xB8, 0x97, 0xE4, 0x90, 0x8C, 0x79,
            0x6F, 0x85, 0x24, 0x84, 0xAE, 0x39, 0x26, 0xB3, 0xB8, 0x1B,
        ])
        .unwrap();

        assert_eq!(cose_doc.get_payload(Some(&ec_public)).unwrap(), TEXT);
    }

    #[test]
    fn cose_sign1_ec256_text() {
        let (ec_private, ec_public) = generate_ec256_test_key();
        let mut map = HeaderMap::new();
        map.insert(CborValue::Integer(4), CborValue::Bytes(b"11".to_vec()));

        let cose_doc1 = COSESign1::new(TEXT, &map, &ec_private).unwrap();
        let cose_doc2 = COSESign1::from_bytes(&cose_doc1.as_bytes(false).unwrap()).unwrap();

        assert_eq!(
            cose_doc1.get_payload(None).unwrap(),
            cose_doc2.get_payload(Some(&ec_public)).unwrap()
        );
    }

    #[test]
    fn cose_sign1_ec384_text() {
        let (ec_private, ec_public) = generate_ec384_test_key();
        let mut map = HeaderMap::new();
        map.insert(CborValue::Integer(4), CborValue::Bytes(b"11".to_vec()));

        let cose_doc1 = COSESign1::new(TEXT, &map, &ec_private).unwrap();
        let cose_doc2 = COSESign1::from_bytes(&cose_doc1.as_bytes(false).unwrap()).unwrap();

        assert_eq!(
            cose_doc1.get_payload(None).unwrap(),
            cose_doc2.get_payload(Some(&ec_public)).unwrap()
        );
    }

    #[test]
    fn cose_sign1_ec512_text() {
        let (ec_private, ec_public) = generate_ec512_test_key();
        let mut map = HeaderMap::new();
        map.insert(CborValue::Integer(4), CborValue::Bytes(b"11".to_vec()));

        let cose_doc1 = COSESign1::new(TEXT, &map, &ec_private).unwrap();
        let cose_doc2 = COSESign1::from_bytes(&cose_doc1.as_bytes(false).unwrap()).unwrap();

        assert_eq!(
            cose_doc1.get_payload(Some(&ec_public)).unwrap(),
            TEXT.to_vec()
        );
        assert_eq!(
            cose_doc1.get_payload(None).unwrap(),
            cose_doc2.get_payload(Some(&ec_public)).unwrap()
        );
    }

    #[test]
    fn unknown_curve() {
        let alg = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1).unwrap();
        let ec_private = openssl::ec::EcKey::generate(&alg).unwrap();
        let map = HeaderMap::new();
        let result = COSESign1::new(TEXT, &map, &ec_private);
        assert!(result.is_err());
    }

    #[test]
    fn validate_with_wrong_key() {
        let (ec_private, ec_public) = generate_ec512_test_key();
        let (_, ec_public_other) = generate_ec512_test_key();
        let mut map = HeaderMap::new();
        map.insert(CborValue::Integer(4), CborValue::Bytes(b"11".to_vec()));

        let cose_doc1 = COSESign1::new(TEXT, &map, &ec_private).unwrap();

        assert!(cose_doc1.verify_signature(&ec_public).unwrap());
        assert!(!cose_doc1.verify_signature(&ec_public_other).unwrap());
    }

    #[test]
    fn validate_with_wrong_key_type() {
        let (ec_private, ec_public) = generate_ec512_test_key();
        let (_, ec_public_other) = generate_ec384_test_key();
        let mut map = HeaderMap::new();
        map.insert(CborValue::Integer(4), CborValue::Bytes(b"11".to_vec()));

        let cose_doc1 = COSESign1::new(TEXT, &map, &ec_private).unwrap();

        assert!(cose_doc1.verify_signature(&ec_public).unwrap());
        assert!(!cose_doc1.verify_signature(&ec_public_other).unwrap());
    }

    #[test]
    fn cose_sign1_ec256_tampered_content() {
        let (_, ec_public) = get_ec256_test_key();

        let cose_doc = COSESign1::from_bytes(&vec![
            0x84, /* Protected: {1: -7} */
            0x43, 0xA1, 0x01, 0x26, /* Unprotected: {4: '11'} */
            0xA1, 0x04, 0x42, 0x31, 0x31, /* payload: */
            0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
            0x68, 0x20, 0x75, 0x6F, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
            0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
            0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
            0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
            0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
            0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
            0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
            0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E, /* Signature - length 32 x 2 */
            0x58, 0x40, /* R: */
            0x6E, 0x6D, 0xF6, 0x54, 0x89, 0xEA, 0x3B, 0x01, 0x88, 0x33, 0xF5, 0xFC, 0x4F, 0x84,
            0xF8, 0x1B, 0x4D, 0x5E, 0xFD, 0x5A, 0x09, 0xD5, 0xC6, 0x2F, 0x2E, 0x92, 0x38, 0x5D,
            0xCE, 0x31, 0xE2, 0xD1, /* S: */
            0x5A, 0x53, 0xA9, 0xF0, 0x75, 0xE8, 0xFB, 0x39, 0x66, 0x9F, 0xCD, 0x4E, 0xB5, 0x22,
            0xC8, 0x5C, 0x92, 0x77, 0x45, 0x2F, 0xA8, 0x57, 0xF5, 0xFE, 0x37, 0x9E, 0xDD, 0xEF,
            0x0F, 0xAB, 0x3C, 0xDD,
        ])
        .unwrap();

        assert!(cose_doc.get_payload(Some(&ec_public)).is_err());
    }

    #[test]
    fn cose_sign1_ec256_tampered_signature() {
        let (_, ec_public) = get_ec256_test_key();

        let cose_doc = COSESign1::from_bytes(&vec![
            0x84, /* Protected: {1: -7} */
            0x43, 0xA1, 0x01, 0x26, /* Unprotected: {4: '11'} */
            0xA1, 0x04, 0x42, 0x31, 0x31, /* payload: */
            0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
            0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
            0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
            0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
            0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
            0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
            0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
            0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
            0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E, /* Signature - length 32 x 2 */
            0x58, 0x40, /* R: */
            0x6E, 0x6D, 0xF6, 0x54, 0x89, 0xEA, 0x3B, 0x01, 0x88, 0x33, 0xF5, 0xFC, 0x4F, 0x84,
            0xF8, 0x1B, 0x4D, 0x5E, 0xFD, 0x5B, 0x09, 0xD5, 0xC6, 0x2F, 0x2E, 0x92, 0x38, 0x5D,
            0xCE, 0x31, 0xE2, 0xD1, /* S: */
            0x5A, 0x53, 0xA9, 0xF0, 0x75, 0xE8, 0xFB, 0x39, 0x66, 0x9F, 0xCD, 0x4E, 0xB5, 0x22,
            0xC8, 0x5C, 0x92, 0x77, 0x45, 0x2F, 0xA8, 0x57, 0xF5, 0xFE, 0x37, 0x9E, 0xDD, 0xEF,
            0x0F, 0xAB, 0x3C, 0xDD,
        ])
        .unwrap();

        assert!(cose_doc.get_payload(Some(&ec_public)).is_err());
    }
}
