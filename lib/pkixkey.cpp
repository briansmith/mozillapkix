/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This code is made available to you under your choice of the following sets
 * of licensing terms:
 */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
/* Copyright 2015 Mozilla Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "pkixutil.h"

namespace mozilla { namespace pkix {

// RFC 5280 Section 4.1.2.7 Subject Public Key Info
Result
CheckSubjectPublicKeyInfo(Reader& input, TrustDomain& trustDomain,
                          EndEntityOrCA endEntityOrCA)
{
  // Here, we validate the syntax and do very basic semantic validation of the
  // public key of the certificate. The intention here is to filter out the
  // types of bad inputs that are most likely to trigger non-mathematical
  // security vulnerabilities in the TrustDomain, like buffer overflows or the
  // use of unsafe elliptic curves.
  //
  // We don't check (all of) the mathematical properties of the public key here
  // because it is more efficient for the TrustDomain to do it during signature
  // verification and/or other use of the public key. In particular, we
  // delegate the arithmetic validation of the public key, as specified in
  // NIST SP800-56A section 5.6.2, to the TrustDomain, at least for now.

  Reader algorithm;
  Input subjectPublicKey;
  Result rv = der::ExpectTagAndGetValue(input, der::SEQUENCE, algorithm);
  if (rv != Success) {
    return rv;
  }
  rv = der::BitStringWithNoUnusedBits(input, subjectPublicKey);
  if (rv != Success) {
    return rv;
  }
  rv = der::End(input);
  if (rv != Success) {
    return rv;
  }

  Reader subjectPublicKeyReader(subjectPublicKey);

  Reader algorithmOID;
  rv = der::ExpectTagAndGetValue(algorithm, der::OIDTag, algorithmOID);
  if (rv != Success) {
    return rv;
  }

  // RFC 3279 Section 2.3.1
  // python DottedOIDToCode.py rsaEncryption 1.2.840.113549.1.1.1
  static const uint8_t rsaEncryption[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
  };

  // RFC 3279 Section 2.3.5 and RFC 5480 Section 2.1.1
  // python DottedOIDToCode.py id-ecPublicKey 1.2.840.10045.2.1
  static const uint8_t id_ecPublicKey[] = {
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
  };

  if (algorithmOID.MatchRest(id_ecPublicKey)) {
    // An id-ecPublicKey AlgorithmIdentifier has a parameter that identifes
    // the curve being used. Although RFC 5480 specifies multiple forms, we
    // only supported the NamedCurve form, where the curve is identified by an
    // OID.

    Reader namedCurveOIDValue;
    rv = der::ExpectTagAndGetValue(algorithm, der::OIDTag,
                                   namedCurveOIDValue);
    if (rv != Success) {
      return rv;
    }

    // RFC 5480
    // python DottedOIDToCode.py secp256r1 1.2.840.10045.3.1.7
    static const uint8_t secp256r1[] = {
      0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    };

    // RFC 5480
    // python DottedOIDToCode.py secp384r1 1.3.132.0.34
    static const uint8_t secp384r1[] = {
      0x2b, 0x81, 0x04, 0x00, 0x22
    };

    // RFC 5480
    // python DottedOIDToCode.py secp521r1 1.3.132.0.35
    static const uint8_t secp521r1[] = {
      0x2b, 0x81, 0x04, 0x00, 0x23
    };

    // Matching is attempted based on a rough estimate of the commonality of the
    // elliptic curve, to minimize the number of MatchRest calls.
    NamedCurve curve;
    unsigned int bits;
    if (namedCurveOIDValue.MatchRest(secp256r1)) {
      curve = NamedCurve::secp256r1;
      bits = 256;
    } else if (namedCurveOIDValue.MatchRest(secp384r1)) {
      curve = NamedCurve::secp384r1;
      bits = 384;
    } else if (namedCurveOIDValue.MatchRest(secp521r1)) {
      curve = NamedCurve::secp521r1;
      bits = 521;
    } else {
      return Result::ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
    }

    rv = trustDomain.CheckECDSACurveIsAcceptable(endEntityOrCA, curve);
    if (rv != Success) {
      return rv;
    }

    // RFC 5480 Section 2.2 says that the first octet will be 0x04 to indicate
    // an uncompressed point, which is the only encoding we support.
    uint8_t compressedOrUncompressed;
    rv = subjectPublicKeyReader.Read(compressedOrUncompressed);
    if (rv != Success) {
      return rv;
    }
    if (compressedOrUncompressed != 0x04) {
      return Result::ERROR_UNSUPPORTED_EC_POINT_FORM;
    }

    // The point is encoded as two raw (not DER-encoded) integers, each padded
    // to the bit length (rounded up to the nearest byte).
    Input point;
    rv = subjectPublicKeyReader.SkipToEnd(point);
    if (rv != Success) {
      return rv;
    }
    if (point.GetLength() != ((bits + 7) / 8u) * 2u) {
      return Result::ERROR_BAD_DER;
    }

    // XXX: We defer the mathematical verification of the validity of the point
    // until signature verification. This means that if we never verify a
    // signature, we'll never fully check whether the public key is valid.
  } else if (algorithmOID.MatchRest(rsaEncryption)) {
    // RFC 3279 Section 2.3.1 says "The parameters field MUST have ASN.1 type
    // NULL for this algorithm identifier."
    rv = der::ExpectTagAndEmptyValue(algorithm, der::NULLTag);
    if (rv != Success) {
      return rv;
    }

    // RSAPublicKey :: = SEQUENCE{
    //    modulus            INTEGER,    --n
    //    publicExponent     INTEGER  }  --e
    rv = der::Nested(subjectPublicKeyReader, der::SEQUENCE,
                     [&trustDomain, endEntityOrCA](Reader& r) {
      Input modulus;
      Input::size_type modulusSignificantBytes;
      Result rv = der::PositiveInteger(r, modulus, &modulusSignificantBytes);
      if (rv != Success) {
        return rv;
      }
      // XXX: Should we do additional checks of the modulus?
      rv = trustDomain.CheckRSAPublicKeyModulusSizeInBits(
             endEntityOrCA, modulusSignificantBytes * 8u);
      if (rv != Success) {
        return rv;
      }

      // XXX: We don't allow the TrustDomain to validate the exponent.
      // XXX: We don't do our own sanity checking of the exponent.
      Input exponent;
      return der::PositiveInteger(r, exponent);
    });
    if (rv != Success) {
      return rv;
    }
  } else {
    return Result::ERROR_UNSUPPORTED_KEYALG;
  }

  rv = der::End(algorithm);
  if (rv != Success) {
    return rv;
  }
  rv = der::End(subjectPublicKeyReader);
  if (rv != Success) {
    return rv;
  }

  return Success;
}

Result
DigestSignedData(TrustDomain& trustDomain,
                 const der::SignedDataWithSignature& signedData,
                 /*out*/ uint8_t(&digestBuf)[MAX_DIGEST_SIZE_IN_BYTES],
                 /*out*/ der::PublicKeyAlgorithm& publicKeyAlg,
                 /*out*/ SignedDigest& signedDigest)
{
  Reader signatureAlg(signedData.algorithm);
  Result rv = der::SignatureAlgorithmIdentifierValue(
                signatureAlg, publicKeyAlg, signedDigest.digestAlgorithm);
  if (rv != Success) {
    return rv;
  }
  if (!signatureAlg.AtEnd()) {
    return Result::ERROR_BAD_DER;
  }

  size_t digestLen;
  switch (signedDigest.digestAlgorithm) {
    case DigestAlgorithm::sha512: digestLen = 512 / 8; break;
    case DigestAlgorithm::sha384: digestLen = 384 / 8; break;
    case DigestAlgorithm::sha256: digestLen = 256 / 8; break;
    case DigestAlgorithm::sha1: digestLen = 160 / 8; break;
    MOZILLA_PKIX_UNREACHABLE_DEFAULT_ENUM
  }
  assert(digestLen <= sizeof(digestBuf));

  rv = trustDomain.DigestBuf(signedData.data, signedDigest.digestAlgorithm,
                             digestBuf, digestLen);
  if (rv != Success) {
    return rv;
  }
  rv = signedDigest.digest.Init(digestBuf, digestLen);
  if (rv != Success) {
    return rv;
  }

  return signedDigest.signature.Init(signedData.signature);
}

Result
VerifySignedDigest(TrustDomain& trustDomain,
                   der::PublicKeyAlgorithm publicKeyAlg,
                   const SignedDigest& signedDigest,
                   Input signerSubjectPublicKeyInfo)
{
  switch (publicKeyAlg) {
    case der::PublicKeyAlgorithm::ECDSA:
      return trustDomain.VerifyECDSASignedDigest(signedDigest,
                                                 signerSubjectPublicKeyInfo);
    case der::PublicKeyAlgorithm::RSA_PKCS1:
      return trustDomain.VerifyRSAPKCS1SignedDigest(signedDigest,
                                                    signerSubjectPublicKeyInfo);
    MOZILLA_PKIX_UNREACHABLE_DEFAULT_ENUM
  }
}

Result
VerifySignedData(TrustDomain& trustDomain,
                 const der::SignedDataWithSignature& signedData,
                 Input signerSubjectPublicKeyInfo)
{
  uint8_t digestBuf[MAX_DIGEST_SIZE_IN_BYTES];
  der::PublicKeyAlgorithm publicKeyAlg;
  SignedDigest signedDigest;
  Result rv = DigestSignedData(trustDomain, signedData, digestBuf,
                               publicKeyAlg, signedDigest);
  if (rv != Success) {
    return rv;
  }
  return VerifySignedDigest(trustDomain, publicKeyAlg, signedDigest,
                            signerSubjectPublicKeyInfo);
}

} } // namespace mozilla::pkix
