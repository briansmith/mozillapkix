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

#include "pkixtestutil.h"

#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include "openssl/md5.h"
#include "openssl/obj_mac.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "pkix/pkixlibcrypto.h"
#include "pkixlibcryptointernal.h"
#include "pkixder.h"
#include "pkixutil.h"
#include "ScopedPtr.h"

namespace mozilla { namespace pkix { namespace test {

namespace {

typedef ScopedPtr<EC_KEY, EC_KEY_free> ScopedEC_KEY;
typedef ScopedPtr<RSA, RSA_free> ScopedRSA;

class LibCryptoTestKeyPair final : public TestKeyPair
{
public:
  LibCryptoTestKeyPair(const TestPublicKeyAlgorithm& publicKeyAlg,
                       const ByteString& spk,
                       /*optional, transfers ownership*/ EC_KEY* ec,
                       /*optional, transfers ownership*/ RSA* rsa)
    : TestKeyPair(publicKeyAlg, spk)
    , ec(ec)
    , rsa(rsa)
  {
    assert((this->ec && !this->rsa) || (!this->ec && this->rsa));
  }

  LibCryptoTestKeyPair(const LibCryptoTestKeyPair&) = delete;
  void operator=(const LibCryptoTestKeyPair&) = delete;

  Result SignData(const ByteString& tbs,
                  const TestSignatureAlgorithm& signatureAlg,
                  /*out*/ ByteString& signature) const override;

  TestKeyPair* Clone() const override
  {
    EC_KEY* ecCopy = nullptr;
    RSA* rsaCopy = nullptr;

    if (ec) {
      ecCopy = EC_KEY_dup(ec.get());
      if (!ecCopy) {
        return nullptr;
      }
    } else {
      assert(rsa);
      rsaCopy = RSAPrivateKey_dup(rsa.get());
      if (!rsaCopy) {
        return nullptr;
      }
    }

    return new (std::nothrow) LibCryptoTestKeyPair(publicKeyAlg,
                                                   subjectPublicKey, ecCopy,
                                                   rsaCopy);
  }

private:
  ScopedEC_KEY ec;
  ScopedRSA rsa;
};

Result LibCryptoTestKeyPair::SignData(
  const ByteString& tbs, const TestSignatureAlgorithm& signatureAlg,
  /*out*/ ByteString& signature) const
{
  assert((rsa && !ec) || (!rsa && ec));

  // Figure out which signature algorithm to use.
  size_t digestLen;
  int digestNID;
  Result rv;
  uint8_t digestBuf[SHA512_DIGEST_LENGTH];
  Input tbsInput;
  if (tbsInput.Init(tbs.data(), tbs.size()) != Input::OK) {
    abort();
  }

  switch (signatureAlg.digestAlg) {
    case TestDigestAlgorithmID::MD2:
      abort();
      break;
    case TestDigestAlgorithmID::MD5: {
      digestLen = MD5_DIGEST_LENGTH;
      digestNID = NID_md5;
      MD5_CTX ctx;
      rv = DigestBufLibCryptoInternal(ctx, MD5_DIGEST_LENGTH, MD5_Init,
                                      MD5_Update, MD5_Final, tbsInput,
                                      digestBuf, MD5_DIGEST_LENGTH);
      break;
    }
    case TestDigestAlgorithmID::SHA1: {
      digestLen = SHA_DIGEST_LENGTH;
      digestNID = NID_sha1;
      SHA_CTX ctx;
      rv = DigestBufLibCryptoInternal(ctx, SHA_DIGEST_LENGTH, SHA1_Init,
                                      SHA1_Update, SHA1_Final, tbsInput,
                                      digestBuf, SHA_DIGEST_LENGTH);
      break;
    }
    case TestDigestAlgorithmID::SHA224: {
      digestLen = SHA224_DIGEST_LENGTH;
      digestNID = NID_sha224;
      SHA256_CTX ctx;
      rv = DigestBufLibCryptoInternal(ctx, SHA224_DIGEST_LENGTH, SHA224_Init,
                                      SHA224_Update, SHA224_Final, tbsInput,
                                      digestBuf, SHA224_DIGEST_LENGTH);
      break;
    }
    case TestDigestAlgorithmID::SHA256: {
      digestLen = SHA256_DIGEST_LENGTH;
      digestNID = NID_sha256;
      SHA256_CTX ctx;
      rv = DigestBufLibCryptoInternal(ctx, SHA256_DIGEST_LENGTH, SHA256_Init,
                                      SHA256_Update, SHA256_Final, tbsInput,
                                      digestBuf, SHA256_DIGEST_LENGTH);
      break;
    }
    case TestDigestAlgorithmID::SHA384: {
      digestLen = SHA384_DIGEST_LENGTH;
      digestNID = NID_sha384;
      SHA512_CTX ctx;
      rv = DigestBufLibCryptoInternal(ctx, SHA384_DIGEST_LENGTH, SHA384_Init,
                                      SHA384_Update, SHA384_Final, tbsInput,
                                      digestBuf, SHA384_DIGEST_LENGTH);
      break;
    }
    case TestDigestAlgorithmID::SHA512: {
      digestLen = SHA512_DIGEST_LENGTH;
      digestNID = NID_sha512;
      SHA512_CTX ctx;
      rv = DigestBufLibCryptoInternal(ctx, SHA512_DIGEST_LENGTH, SHA512_Init,
                                      SHA512_Update, SHA512_Final, tbsInput,
                                      digestBuf, SHA512_DIGEST_LENGTH);
      break;
    }
    default:
      abort();
  }

  if (rv != Success) {
    abort();
  }

  uint8_t buf[16384 / 8];

  assert(signatureAlg.publicKeyAlg == RSA_PKCS1());
  if (!rsa) {
    return NotReached("No RSA key for RSA-PKCS#1 signature",
                      Result::FATAL_ERROR_LIBRARY_FAILURE);
  }

  unsigned int sigLen = RSA_size(rsa.get());
  if (!sigLen) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  if (sigLen > sizeof(buf)) {
    return NotReached("Buffer too small for RSA signature",
                      Result::FATAL_ERROR_LIBRARY_FAILURE);
  }
  unsigned int actualSigLen = sigLen;
  if (RSA_sign(digestNID, digestBuf, digestLen, buf, &actualSigLen,
      rsa.get()) != 1) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  if (actualSigLen != sigLen) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  signature.assign(buf, actualSigLen);
  return Success;
}



ByteString
DERIntegerFromBIGNUM(const BIGNUM* n)
{
  assert(n);

  uint8_t buffer[1024];

  size_t len = static_cast<size_t>(BN_num_bytes(n));
  if (len <= 0) {
    abort();
  }
  if (len > sizeof(buffer)) {
    abort();
  }
  if (static_cast<size_t>(BN_bn2bin(n, buffer)) != len) {
    abort();
  }
  ByteString value(buffer, len);
  if (value[0] & 0x80) {
    value.insert(0, 1, 0x00);
  }
  return TLV(der::INTEGER, value);
}

} // unnamed namespace

TestKeyPair*
GenerateKeyPair()
{
  ScopedRSA rsa(RSA_new());
  if (!rsa) {
    abort();
  }
  ScopedPtr<BIGNUM, BN_free> exponent(BN_new());
  if (!exponent) {
    abort();
  }
  if (BN_set_word(exponent.get(), RSA_3) != 1) {
    abort();
  }
  if (RSA_generate_key_ex(rsa.get(), 2048, exponent.get(), nullptr) != 1) {
    abort();
  }

  // RFC 3279 Section 2.3.1
  // python DottedOIDToCode.py rsaEncryption 1.2.840.113549.1.1.1
  static const uint8_t rsaEncryption[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
  };

  ByteString rsaEncryptionBS(rsaEncryption, sizeof(rsaEncryption));

  // DER-encode the public key (see notes above about why we don't use the
  // OpenSSL DER encoding functions).
  ByteString spk(TLV(der::SEQUENCE, DERIntegerFromBIGNUM(rsa->n) +
                                    DERIntegerFromBIGNUM(rsa->e)));

  static const uint8_t NO_UNUSED_BITS[1] = { 0x00 };
  ByteString spki(TLV(der::SEQUENCE,
                      TLV(der::SEQUENCE,
                          TLV(der::OIDTag, rsaEncryptionBS) +
                          TLV(der::NULLTag, ByteString())) +
                      TLV(der::BIT_STRING,
                          ByteString(NO_UNUSED_BITS, sizeof(NO_UNUSED_BITS)) +
                          spk)));
  TestKeyPair* result = new (std::nothrow) LibCryptoTestKeyPair(RSA_PKCS1(), spk, nullptr,
                                                        rsa.release());
  if (!result) {
    abort();
  }
  return result;
}

TestKeyPair*
CloneReusedKeyPair()
{
  // TODO: thread safety.
  static ScopedTestKeyPair reusedKeyPair;
  if (!reusedKeyPair) {
    reusedKeyPair.reset(GenerateKeyPair());
    if (!reusedKeyPair) {
      abort();
    }
  }
  return reusedKeyPair->Clone();
}

Result
TestVerifyECDSASignedDigest(const SignedDigest& signedDigest,
                            Input /*subjectPublicKeyInfo*/, NamedCurve curve,
                            Input publicPoint)
{
  return VerifyECDSASignedDigestLibCrypto(signedDigest, curve, publicPoint);
}

Result
TestVerifyRSAPKCS1SignedDigest(const SignedDigest& signedDigest,
                               Input /*subjectPublicKeyInfo*/,
                               Input rsaPublicKey)
{
  return VerifyRSAPKCS1SignedDigestLibCrypto(signedDigest, rsaPublicKey);
}

Result
TestDigestBuf(Input item, DigestAlgorithm digestAlg,
              /*out*/ uint8_t* digestBuf, size_t digestBufLen)
{
  return DigestBufLibCrypto(item, digestAlg, digestBuf, digestBufLen);
}

} } } // namespace mozilla::pkix::test
