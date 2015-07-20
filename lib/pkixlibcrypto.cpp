/*- *- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
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

#include "pkix/pkixlibcrypto.h"

#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include "openssl/objects.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"
#include "pkixlibcryptointernal.h"
#include "ScopedPtr.h"

namespace mozilla { namespace pkix {

namespace {

typedef ScopedPtr<BIGNUM, BN_free> ScopedBIGNUM;

} // namespace

Result
DigestBufLibCrypto(Input item, DigestAlgorithm digestAlg,
                   /*out*/ uint8_t* digestBuf, size_t digestBufLen)
{
  switch (digestAlg) {
    case DigestAlgorithm::sha512: {
      SHA512_CTX ctx;
      return DigestBufLibCryptoInternal(ctx, SHA512_DIGEST_LENGTH, SHA512_Init,
                                        SHA512_Update, SHA512_Final, item,
                                        digestBuf, digestBufLen);
    }
    case DigestAlgorithm::sha384: {
      SHA512_CTX ctx;
      return DigestBufLibCryptoInternal(ctx, SHA384_DIGEST_LENGTH, SHA384_Init,
                                        SHA384_Update, SHA384_Final, item,
                                        digestBuf, digestBufLen);
    }
    case DigestAlgorithm::sha256: {
      SHA256_CTX ctx;
      return DigestBufLibCryptoInternal(ctx, SHA256_DIGEST_LENGTH, SHA256_Init,
                                        SHA256_Update, SHA256_Final, item,
                                        digestBuf, digestBufLen);
    }
    case DigestAlgorithm::sha1: {
      SHA_CTX ctx;
      return DigestBufLibCryptoInternal(ctx, SHA_DIGEST_LENGTH, SHA1_Init,
                                        SHA1_Update, SHA1_Final, item,
                                        digestBuf, digestBufLen);
    }
    default:
      return Result::ERROR_INVALID_ALGORITHM;
  }
}

Result VerifyECDSASignedDigestLibCrypto(const SignedDigest& signedDigest,
                                        Input r, Input s, NamedCurve curve,
                                        Input publicPoint)
{
  int groupNID;
  switch (curve) {
    case NamedCurve::secp256r1: groupNID = NID_X9_62_prime256v1; break;
    case NamedCurve::secp384r1: groupNID = NID_secp384r1; break;
    case NamedCurve::secp521r1: groupNID = NID_secp521r1; break;
    default:
      return Result::ERROR_UNSUPPORTED_ELLIPTIC_CURVE;
  }
  ScopedPtr<EC_GROUP, EC_GROUP_free>
    group(EC_GROUP_new_by_curve_name(groupNID));
  if (!group) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  ScopedPtr<EC_POINT, EC_POINT_free> point(EC_POINT_new(group.get()));
  ScopedPtr<EC_KEY, EC_KEY_free> key(EC_KEY_new());
  if (!point ||
      !key ||
      (EC_KEY_set_group(key.get(), group.get()) != 1)) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  if ((EC_POINT_oct2point(group.get(), point.get(), publicPoint.UnsafeGetData(),
                          publicPoint.GetLength(), nullptr) != 1) ||
      (EC_KEY_set_public_key(key.get(), point.get()) != 1)) {
    return Result::ERROR_INVALID_KEY;
  }

  // |r| and |s| aren't allocated on the stack because the OpenSSL trunk has
  // made BIGNUM an opaque type, and we want to share this code across all
  // variants of OpenSSL.
  ScopedBIGNUM r_bn(BN_bin2bn(r.UnsafeGetData(), r.GetLength(), nullptr));
  if (!r_bn) {
    return Result::FATAL_ERROR_NO_MEMORY;
  }
  ScopedBIGNUM s_bn(BN_bin2bn(s.UnsafeGetData(), s.GetLength(), nullptr));
  if (!s_bn) {
    return Result::FATAL_ERROR_NO_MEMORY;
  }
  ECDSA_SIG sig;
  sig.r = r_bn.get();
  sig.s = s_bn.get();

  if (ECDSA_do_verify(signedDigest.digest.UnsafeGetData(),
                      signedDigest.digest.GetLength(), &sig, key.get()) != 1) {
    return Result::ERROR_BAD_SIGNATURE;
  }

  return Success;
}

Result VerifyRSAPKCS1SignedDigestLibCrypto(const SignedDigest& signedDigest,
                                           Input modulus, Input exponent)
{
  ScopedBIGNUM n(BN_bin2bn(modulus.UnsafeGetData(), modulus.GetLength(),
                           nullptr));
  if (!n) {
    return Result::FATAL_ERROR_NO_MEMORY;
  }
  ScopedBIGNUM e(BN_bin2bn(exponent.UnsafeGetData(), exponent.GetLength(),
                           nullptr));
  if (!e) {
    return Result::FATAL_ERROR_NO_MEMORY;
  }
  ScopedPtr<RSA, RSA_free> key(RSA_new());
  if (!key) {
    return Result::FATAL_ERROR_NO_MEMORY;
  }
  key->n = n.release();
  key->e = e.release();

  int digestNID;
  switch (signedDigest.digestAlgorithm) {
    case DigestAlgorithm::sha512: digestNID = NID_sha512; break;
    case DigestAlgorithm::sha384: digestNID = NID_sha384; break;
    case DigestAlgorithm::sha256: digestNID = NID_sha256; break;
    case DigestAlgorithm::sha1: digestNID = NID_sha1; break;
    default:
      return Result::ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED;
  }

  if (RSA_verify(digestNID, signedDigest.digest.UnsafeGetData(),
                 signedDigest.digest.GetLength(),
                 signedDigest.signature.UnsafeGetData(),
                 signedDigest.signature.GetLength(), key.get()) != 1) {
    return Result::ERROR_BAD_SIGNATURE;
  }

  return Success;
}

} } // namespace mozilla::pkix
