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

#include "pkixgtest.h"

#include "pkixutil.h"

using namespace mozilla::pkix;
using namespace mozilla::pkix::test;

struct SyntacticallyValidRSAKeyParams
{
  ByteString modulusValue;
  ByteString exponentValue;
  unsigned int modulusSizeInBits;
};

static const ByteString NO_UNUSED_BITS(1, 0x00);

template <size_t SIZE>
static ByteString
BS(const char(&value)[SIZE])
{
  assert(value[SIZE - 1] == 0); // null terminated.
  return ByteString(reinterpret_cast<const uint8_t*>(&value), SIZE - 1u);
}

static const SyntacticallyValidRSAKeyParams SYNTACTICALLY_VALID_RSA_KEYS[] =
{
  { // Not a valid key but syntactically valid.
    BS("\x7F"),
    BS("\x7F"),
    8,
  },
  { // Not a valid key but syntactically valid. The prefix 0x00 used to
    // disambiguate the value from a negative number isn't counted as part of
    // the size or values passed to VerifyRSAPKCS1SignedDigest.
    BS("\x00\xFF"),
    BS("\x00\xFF"),
    8,
  },
  { // A realistically-sized modulus and a common exponent (3)
    ByteString(2048 / 8, 0x30),
    BS("\x03"),
    2048,
  },
  { // A realistically-sized modulus and a common exponent (65537)
    ByteString(2048 / 8, 0x30),
    BS("\x01\x00\x01"),
    2048,
  },
  { // A very large modulus
    ByteString(32 * 1024 / 8, 0x30),
    BS("\x03"),
    32 * 1024,
  },
  { // A modulus that isn't a multiple of 16 bytes
    ByteString(32 * 1024 / 8 + 1, 0x30),
    BS("\x03"),
    32 * 1024 + 8,
  },
};

class pkixkey_SyntacticallyValidRSAKey
  : public ::testing::Test
  , public ::testing::WithParamInterface<SyntacticallyValidRSAKeyParams>
{
};

class pkixkey_SyntacticallyValidRSAKeyTrustDomain final
  : public EverythingFailsByDefaultTrustDomain
{
public:
  pkixkey_SyntacticallyValidRSAKeyTrustDomain(
    unsigned int expectedModulusSizeInBits,
    const ByteString& expectedModulus,
    const ByteString& expectedExponent)
    : modulusSizeChecked(false)
    , verified(false)
    , expectedModulusSizeInBits(expectedModulusSizeInBits)
    , expectedModulus(expectedModulus)
    , expectedExponent(expectedExponent)
  {
  }

  Result CheckRSAPublicKeyModulusSizeInBits(EndEntityOrCA,
                                            unsigned int modulusSizeInBits)
                                            override
  {
    EXPECT_FALSE(modulusSizeChecked);
    modulusSizeChecked = true;
    EXPECT_EQ(expectedModulusSizeInBits, modulusSizeInBits);
    return Success;
  }

  Result VerifyRSAPKCS1SignedDigest(const SignedDigest&,
                                    Input /*subjectPublicKeyInfo*/,
                                    Input modulus, Input exponent)
                                    override
  {
    EXPECT_TRUE(modulusSizeChecked);
    EXPECT_FALSE(verified);
    verified = true;
    EXPECT_TRUE(InputEqualsByteString(modulus, expectedModulus));
    EXPECT_TRUE(InputEqualsByteString(exponent, expectedExponent));
    return Success;
  }

  bool modulusSizeChecked;
  bool verified;
  const unsigned int expectedModulusSizeInBits;
  const ByteString expectedModulus;
  const ByteString expectedExponent;
};

TEST_P(pkixkey_SyntacticallyValidRSAKey, Test)
{
  const SyntacticallyValidRSAKeyParams& params(GetParam());

  ByteString spk(TLV(der::SEQUENCE,
                     TLV(der::INTEGER, params.modulusValue) +
                     TLV(der::INTEGER, params.exponentValue)));
  ByteString spki(TLV(der::SEQUENCE,
                      RSA_PKCS1().algorithmIdentifier +
                      TLV(der::BIT_STRING, NO_UNUSED_BITS + spk)));

  Input spkiInput;
  ASSERT_EQ(Input::OK, spkiInput.Init(spki.data(), spki.length()));

  PublicKey key;
  ASSERT_EQ(Success, key.Init(EndEntityOrCA::MustBeEndEntity, spkiInput));

  pkixkey_SyntacticallyValidRSAKeyTrustDomain
    trustDomain(params.modulusSizeInBits, params.modulusValue,
                params.exponentValue);

  ASSERT_EQ(Success, key.ParseAndCheck(trustDomain));

  EXPECT_TRUE(trustDomain.modulusSizeChecked);
  EXPECT_FALSE(trustDomain.verified);

  SignedDigest signedDigest;
  ASSERT_EQ(Success,
            key.VerifySignedDigest(trustDomain,
                                   der::PublicKeyAlgorithm::RSA_PKCS1,
                                   signedDigest));
}

INSTANTIATE_TEST_CASE_P(pkixkey_SyntacticallyValidRSAKey,
                        pkixkey_SyntacticallyValidRSAKey,
                        testing::ValuesIn(SYNTACTICALLY_VALID_RSA_KEYS));

static const ByteString SYNTACTICALLY_INVALID_RSA_KEYS[] =
{
  ByteString(),

  // Zero is not considered a syntactically-valid modulus
  TLV(der::SEQUENCE,
      TLV(der::INTEGER, BS("\x00")) +
      TLV(der::INTEGER, BS("\x03"))),

  // Zero is not considered a syntactically-valid exponent
  TLV(der::SEQUENCE,
      TLV(der::INTEGER, BS("\x03")) +
      TLV(der::INTEGER, BS("\x00"))),

  // Negative modulus is not accepted.
  TLV(der::SEQUENCE,
      TLV(der::INTEGER, BS("\x80")) +
      TLV(der::INTEGER, BS("\x03"))),

  // Negative exponent is not accepted (note that it is odd, so that the test
  // makes sense even if we start rejecting even exponents in the future).
  TLV(der::SEQUENCE,
      TLV(der::INTEGER, BS("\x01")) +
      TLV(der::INTEGER, BS("\x81"))),
};

class pkixkey_SyntacticallyInvalidRSAKey
  : public ::testing::Test
  , public ::testing::WithParamInterface<ByteString>
{
};

TEST_P(pkixkey_SyntacticallyInvalidRSAKey, Test)
{
  const ByteString& spki(GetParam());

  Input spkiInput;
  ASSERT_EQ(Input::OK, spkiInput.Init(spki.data(), spki.length()));

  PublicKey key;
  ASSERT_EQ(Success, key.Init(EndEntityOrCA::MustBeEndEntity, spkiInput));

  EverythingFailsByDefaultTrustDomain trustDomain;
  ASSERT_EQ(Result::ERROR_BAD_DER, key.ParseAndCheck(trustDomain));
}

INSTANTIATE_TEST_CASE_P(pkixkey_SyntacticallyInvalidRSAKey,
                        pkixkey_SyntacticallyInvalidRSAKey,
                        testing::ValuesIn(SYNTACTICALLY_INVALID_RSA_KEYS));
