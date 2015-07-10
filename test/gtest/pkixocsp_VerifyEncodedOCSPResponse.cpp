/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This code is made available to you under your choice of the following sets
 * of licensing terms:
 */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
/* Copyright 2014 Mozilla Contributors
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

#include "nss.h"
#include "nssgtest.h"
#include "pkix/pkix.h"
#include "pkix/pkixnss.h"
#include "pkixgtest.h"
#include "pkixtestutil.h"
#include "prinit.h"
#include "secerr.h"

using namespace mozilla::pkix;
using namespace mozilla::pkix::test;

const uint16_t END_ENTITY_MAX_LIFETIME_IN_DAYS = 10;

class OCSPTestTrustDomain : public TrustDomain
{
public:
  OCSPTestTrustDomain()
  {
  }

  Result GetCertTrust(EndEntityOrCA endEntityOrCA, const CertPolicyId&,
                      Input, /*out*/ TrustLevel& trustLevel)
  {
    EXPECT_EQ(endEntityOrCA, EndEntityOrCA::MustBeEndEntity);
    trustLevel = TrustLevel::InheritsTrust;
    return Success;
  }

  Result FindIssuer(Input, IssuerChecker&, Time)
  {
    ADD_FAILURE();
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }

  virtual Result CheckRevocation(EndEntityOrCA endEntityOrCA, const CertID&,
                                 Time time, /*optional*/ const Input*,
                                 /*optional*/ const Input*)
  {
    // TODO: I guess mozilla::pkix should support revocation of designated
    // OCSP responder eventually, but we don't now, so this function should
    // never get called.
    ADD_FAILURE();
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }

  virtual Result IsChainValid(const DERArray&)
  {
    ADD_FAILURE();
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }

  virtual Result VerifySignedData(const SignedDataWithSignature& signedData,
                                  Input subjectPublicKeyInfo)
  {
    return ::mozilla::pkix::VerifySignedData(signedData, subjectPublicKeyInfo,
                                             nullptr);
  }

  virtual Result DigestBuf(Input item, /*out*/ uint8_t *digestBuf,
                           size_t digestBufLen)
  {
    return ::mozilla::pkix::DigestBuf(item, digestBuf, digestBufLen);
  }

  virtual Result CheckPublicKey(Input subjectPublicKeyInfo)
  {
    return ::mozilla::pkix::CheckPublicKey(subjectPublicKeyInfo);
  }

private:
  OCSPTestTrustDomain(const OCSPTestTrustDomain&) /*delete*/;
  void operator=(const OCSPTestTrustDomain&) /*delete*/;
};

namespace {
char const* const rootName = "Test CA 1";
void deleteCertID(CertID* certID) { delete certID; }
} // unnamed namespace

class pkixocsp_VerifyEncodedResponse : public NSSTest
{
public:
  static bool SetUpTestCaseInner()
  {
    ScopedSECKEYPublicKey rootPublicKey;
    if (GenerateKeyPair(rootPublicKey, rootPrivateKey) != Success) {
      return false;
    }
    ScopedSECItem rootSPKIItem(
      SECKEY_EncodeDERSubjectPublicKeyInfo(rootPublicKey.get()));
    if (!rootSPKIItem) {
      return false;
    }
    rootSPKI.assign(rootSPKIItem->data, rootSPKIItem->len);
    return true;
  }

  static void SetUpTestCase()
  {
    NSSTest::SetUpTestCase();
    if (!SetUpTestCaseInner()) {
      abort();
    }
  }

  void SetUp()
  {
    NSSTest::SetUp();

    rootNameDER = CNToDERName(rootName);
    if (rootNameDER == ENCODING_FAILED) {
      abort();
    }
    Input rootNameDERInput;
    if (rootNameDERInput.Init(rootNameDER.data(), rootNameDER.length())
          != Success) {
      abort();
    }

    serialNumberDER = CreateEncodedSerialNumber(++rootIssuedCount);
    if (serialNumberDER == ENCODING_FAILED) {
      abort();
    }
    Input serialNumberDERInput;
    if (serialNumberDERInput.Init(serialNumberDER.data(),
                                  serialNumberDER.length()) != Success) {
      abort();
    }

    Input rootSPKIDER;
    if (rootSPKIDER.Init(rootSPKI.data(), rootSPKI.length()) != Success) {
      abort();
    }
    endEntityCertID = new (std::nothrow) CertID(rootNameDERInput, rootSPKIDER,
                                                serialNumberDERInput);
    if (!endEntityCertID) {
      abort();
    }
  }

  static ScopedSECKEYPrivateKey rootPrivateKey;
  static ByteString rootSPKI;
  static long rootIssuedCount;
  OCSPTestTrustDomain trustDomain;

  ByteString rootNameDER;
  ByteString serialNumberDER;
  // endEntityCertID references rootSPKI, rootNameDER, and serialNumberDER.
  ScopedPtr<CertID, deleteCertID> endEntityCertID;
};

/*static*/ ScopedSECKEYPrivateKey
              pkixocsp_VerifyEncodedResponse::rootPrivateKey;
/*static*/ ByteString pkixocsp_VerifyEncodedResponse::rootSPKI;
/*static*/ long pkixocsp_VerifyEncodedResponse::rootIssuedCount = 0;

///////////////////////////////////////////////////////////////////////////////
// responseStatus

struct WithoutResponseBytes
{
  uint8_t responseStatus;
  Result expectedError;
};

static const WithoutResponseBytes WITHOUT_RESPONSEBYTES[] = {
  { OCSPResponseContext::successful, Result::ERROR_OCSP_MALFORMED_RESPONSE },
  { OCSPResponseContext::malformedRequest, Result::ERROR_OCSP_MALFORMED_REQUEST },
  { OCSPResponseContext::internalError, Result::ERROR_OCSP_SERVER_ERROR },
  { OCSPResponseContext::tryLater, Result::ERROR_OCSP_TRY_SERVER_LATER },
  { 4/*unused*/, Result::ERROR_OCSP_UNKNOWN_RESPONSE_STATUS },
  { OCSPResponseContext::sigRequired, Result::ERROR_OCSP_REQUEST_NEEDS_SIG },
  { OCSPResponseContext::unauthorized, Result::ERROR_OCSP_UNAUTHORIZED_REQUEST },
  { OCSPResponseContext::unauthorized + 1,
    Result::ERROR_OCSP_UNKNOWN_RESPONSE_STATUS
  },
};

class pkixocsp_VerifyEncodedResponse_WithoutResponseBytes
  : public pkixocsp_VerifyEncodedResponse
  , public ::testing::WithParamInterface<WithoutResponseBytes>
{
protected:
  ByteString CreateEncodedOCSPErrorResponse(uint8_t status)
  {
    static const Input EMPTY;
    OCSPResponseContext context(CertID(EMPTY, EMPTY, EMPTY),
                                oneDayBeforeNow);
    context.responseStatus = status;
    context.skipResponseBytes = true;
    return CreateEncodedOCSPResponse(context);
  }
};

TEST_P(pkixocsp_VerifyEncodedResponse_WithoutResponseBytes, CorrectErrorCode)
{
  ByteString
    responseString(CreateEncodedOCSPErrorResponse(GetParam().responseStatus));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(GetParam().expectedError,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
}

INSTANTIATE_TEST_CASE_P(pkixocsp_VerifyEncodedResponse_WithoutResponseBytes,
                        pkixocsp_VerifyEncodedResponse_WithoutResponseBytes,
                        testing::ValuesIn(WITHOUT_RESPONSEBYTES));

///////////////////////////////////////////////////////////////////////////////
// "successful" responses

namespace {

// Alias for nullptr to aid readability in the code below.
static const char* byKey = nullptr;

} // unnamed namespcae

class pkixocsp_VerifyEncodedResponse_successful
  : public pkixocsp_VerifyEncodedResponse
{
public:
  void SetUp()
  {
    pkixocsp_VerifyEncodedResponse::SetUp();
  }

  static void SetUpTestCase()
  {
    pkixocsp_VerifyEncodedResponse::SetUpTestCase();
  }

  ByteString CreateEncodedOCSPSuccessfulResponse(
                    OCSPResponseContext::CertStatus certStatus,
                    const CertID& certID,
                    /*optional*/ const char* signerName,
                    const ScopedSECKEYPrivateKey& signerPrivateKey,
                    time_t producedAt, time_t thisUpdate,
                    /*optional*/ const time_t* nextUpdate,
                    /*optional*/ const ByteString* certs = nullptr)
  {
    OCSPResponseContext context(certID, producedAt);
    if (signerName) {
      context.signerNameDER = CNToDERName(signerName);
      EXPECT_NE(ENCODING_FAILED, context.signerNameDER);
    }
    context.signerPrivateKey = SECKEY_CopyPrivateKey(signerPrivateKey.get());
    EXPECT_TRUE(context.signerPrivateKey);
    context.responseStatus = OCSPResponseContext::successful;
    context.producedAt = producedAt;
    context.certs = certs;

    context.certStatus = certStatus;
    context.thisUpdate = thisUpdate;
    context.nextUpdate = nextUpdate ? *nextUpdate : 0;
    context.includeNextUpdate = nextUpdate != nullptr;

    return CreateEncodedOCSPResponse(context);
  }
};

TEST_F(pkixocsp_VerifyEncodedResponse_successful, good_byKey)
{
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID, byKey,
                         rootPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, &oneDayAfterNow));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Success,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID,
                                      Now(), END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_successful, good_byName)
{
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID, rootName,
                         rootPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, &oneDayAfterNow));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Success,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_successful, good_byKey_without_nextUpdate)
{
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID, byKey,
                         rootPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, nullptr));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Success,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_successful, revoked)
{
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::revoked, *endEntityCertID, byKey,
                         rootPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, &oneDayAfterNow));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_REVOKED_CERTIFICATE,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_successful, unknown)
{
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::unknown, *endEntityCertID, byKey,
                         rootPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, &oneDayAfterNow));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_UNKNOWN_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

///////////////////////////////////////////////////////////////////////////////
// indirect responses (signed by a delegated OCSP responder cert)

class pkixocsp_VerifyEncodedResponse_DelegatedResponder
  : public pkixocsp_VerifyEncodedResponse_successful
{
protected:
  // certSubjectName should be unique for each call. This way, we avoid any
  // issues with NSS caching the certificates internally. For the same reason,
  // we generate a new keypair on each call. Either one of these should be
  // sufficient to avoid issues with the NSS cache, but we do both to be
  // cautious.
  //
  // signerName should be byKey to use the byKey ResponderID construction, or
  // another value (usually equal to certSubjectName) to use the byName
  // ResponderID construction.
  //
  // If signerEKU is omitted, then the certificate will have the
  // id-kp-OCSPSigning EKU. If signerEKU is SEC_OID_UNKNOWN then it will not
  // have any EKU extension. Otherwise, the certificate will have the given
  // EKU.
  ByteString CreateEncodedIndirectOCSPSuccessfulResponse(
               const char* certSubjectName,
               OCSPResponseContext::CertStatus certStatus,
               const char* signerName,
               /*optional*/ const Input* signerEKUDER = &OCSPSigningEKUDER,
               /*optional, out*/ ByteString* signerDEROut = nullptr)
  {
    assert(certSubjectName);

    const ByteString extensions[] = {
      signerEKUDER
        ? CreateEncodedEKUExtension(*signerEKUDER,
                                    ExtensionCriticality::NotCritical)
        : ByteString(),
      ByteString()
    };
    ScopedSECKEYPrivateKey signerPrivateKey;
    ByteString signerDER(CreateEncodedCertificate(
                           ++rootIssuedCount, rootName,
                           oneDayBeforeNow, oneDayAfterNow, certSubjectName,
                           signerEKUDER ? extensions : nullptr,
                           rootPrivateKey.get(), signerPrivateKey));
    EXPECT_NE(ENCODING_FAILED, signerDER);
    if (signerDEROut) {
      *signerDEROut = signerDER;
    }

    ByteString signerNameDER;
    if (signerName) {
      signerNameDER = CNToDERName(signerName);
      EXPECT_NE(ENCODING_FAILED, signerNameDER);
    }
    ByteString certs[] = { signerDER, ByteString() };
    return CreateEncodedOCSPSuccessfulResponse(certStatus, *endEntityCertID,
                                               signerName, signerPrivateKey,
                                               oneDayBeforeNow,
                                               oneDayBeforeNow,
                                               &oneDayAfterNow, certs);
  }

  static ByteString CreateEncodedCertificate(uint32_t serialNumber,
                                             const char* issuer,
                                             time_t notBefore,
                                             time_t notAfter,
                                             const char* subject,
                                /*optional*/ const ByteString* extensions,
                                /*optional*/ SECKEYPrivateKey* signerKey,
                                     /*out*/ ScopedSECKEYPrivateKey& privateKey)
  {
    ByteString serialNumberDER(CreateEncodedSerialNumber(serialNumber));
    if (serialNumberDER == ENCODING_FAILED) {
      return ENCODING_FAILED;
    }
    ByteString issuerDER(CNToDERName(issuer));
    if (issuerDER == ENCODING_FAILED) {
      return ENCODING_FAILED;
    }
    ByteString subjectDER(CNToDERName(subject));
    if (subjectDER == ENCODING_FAILED) {
      return ENCODING_FAILED;
    }
    return ::mozilla::pkix::test::CreateEncodedCertificate(
                                    v3,
                                    sha256WithRSAEncryption,
                                    serialNumberDER, issuerDER, notBefore,
                                    notAfter, subjectDER, extensions,
                                    signerKey,
                                    SignatureAlgorithm::rsa_pkcs1_with_sha256,
                                    privateKey);
  }

  static const Input OCSPSigningEKUDER;
};

/*static*/ const Input pkixocsp_VerifyEncodedResponse_DelegatedResponder::
  OCSPSigningEKUDER(tlv_id_kp_OCSPSigning);

TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder, good_byKey)
{
  ByteString responseString(
               CreateEncodedIndirectOCSPSuccessfulResponse(
                         "good_indirect_byKey", OCSPResponseContext::good,
                         byKey));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Success,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder, good_byName)
{
  ByteString responseString(
               CreateEncodedIndirectOCSPSuccessfulResponse(
                         "good_indirect_byName", OCSPResponseContext::good,
                         "good_indirect_byName"));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Success,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder,
       good_byKey_missing_signer)
{
  ScopedSECKEYPublicKey missingSignerPublicKey;
  ScopedSECKEYPrivateKey missingSignerPrivateKey;
  ASSERT_EQ(Success, GenerateKeyPair(missingSignerPublicKey,
                                     missingSignerPrivateKey));
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID, byKey,
                         missingSignerPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, nullptr));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder,
       good_byName_missing_signer)
{
  ScopedSECKEYPublicKey missingSignerPublicKey;
  ScopedSECKEYPrivateKey missingSignerPrivateKey;
  ASSERT_EQ(Success, GenerateKeyPair(missingSignerPublicKey,
                                     missingSignerPrivateKey));
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID,
                         "missing", missingSignerPrivateKey,
                         oneDayBeforeNow, oneDayBeforeNow, nullptr));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder, good_expired)
{
  static const char* signerName = "good_indirect_expired";

  const ByteString extensions[] = {
    CreateEncodedEKUExtension(OCSPSigningEKUDER,
                              ExtensionCriticality::NotCritical),
    ByteString()
  };

  ScopedSECKEYPrivateKey signerPrivateKey;
  ByteString signerDER(CreateEncodedCertificate(
                          ++rootIssuedCount, rootName,
                          now - (10 * Time::ONE_DAY_IN_SECONDS),
                          now - (2 * Time::ONE_DAY_IN_SECONDS),
                          signerName, extensions, rootPrivateKey.get(),
                          signerPrivateKey));
  ASSERT_NE(ENCODING_FAILED, signerDER);

  ByteString certs[] = { signerDER, ByteString() };
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID,
                         signerName, signerPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, &oneDayAfterNow, certs));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
}

TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder, good_future)
{
  static const char* signerName = "good_indirect_future";

  const ByteString extensions[] = {
    CreateEncodedEKUExtension(OCSPSigningEKUDER,
                              ExtensionCriticality::NotCritical),
    ByteString()
  };

  ScopedSECKEYPrivateKey signerPrivateKey;
  ByteString signerDER(CreateEncodedCertificate(
                         ++rootIssuedCount, rootName,
                         now + (2 * Time::ONE_DAY_IN_SECONDS),
                         now + (10 * Time::ONE_DAY_IN_SECONDS),
                         signerName, extensions, rootPrivateKey.get(),
                         signerPrivateKey));
  ASSERT_NE(ENCODING_FAILED, signerDER);

  ByteString certs[] = { signerDER, ByteString() };
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID,
                         signerName, signerPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, &oneDayAfterNow, certs));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder, good_no_eku)
{
  ByteString responseString(
               CreateEncodedIndirectOCSPSuccessfulResponse(
                         "good_indirect_wrong_eku",
                         OCSPResponseContext::good, byKey, nullptr));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

static const Input serverAuthEKUDER(tlv_id_kp_serverAuth);

TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder,
       good_indirect_wrong_eku)
{
  ByteString responseString(
               CreateEncodedIndirectOCSPSuccessfulResponse(
                        "good_indirect_wrong_eku",
                        OCSPResponseContext::good, byKey, &serverAuthEKUDER));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

// Test that signature of OCSP response signer cert is verified
TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder, good_tampered_eku)
{
  ByteString tamperedResponse(
               CreateEncodedIndirectOCSPSuccessfulResponse(
                         "good_indirect_tampered_eku",
                         OCSPResponseContext::good, byKey, &serverAuthEKUDER));
  ASSERT_EQ(Success,
            TamperOnce(tamperedResponse,
                       ByteString(tlv_id_kp_serverAuth,
                                  sizeof(tlv_id_kp_serverAuth)),
                       ByteString(tlv_id_kp_OCSPSigning,
                                  sizeof(tlv_id_kp_OCSPSigning))));
  Input tamperedResponseInput;
  ASSERT_EQ(Success, tamperedResponseInput.Init(tamperedResponse.data(),
                                                tamperedResponse.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      tamperedResponseInput, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder, good_unknown_issuer)
{
  static const char* subCAName = "good_indirect_unknown_issuer sub-CA";
  static const char* signerName = "good_indirect_unknown_issuer OCSP signer";

  // unknown issuer
  ScopedSECKEYPublicKey unknownPublicKey;
  ScopedSECKEYPrivateKey unknownPrivateKey;
  ASSERT_EQ(Success, GenerateKeyPair(unknownPublicKey, unknownPrivateKey));

  // Delegated responder cert signed by unknown issuer
  const ByteString extensions[] = {
    CreateEncodedEKUExtension(OCSPSigningEKUDER,
                              ExtensionCriticality::NotCritical),
    ByteString()
  };
  ScopedSECKEYPrivateKey signerPrivateKey;
  ByteString signerDER(CreateEncodedCertificate(
                         1, subCAName, oneDayBeforeNow, oneDayAfterNow,
                         signerName, extensions, unknownPrivateKey.get(),
                         signerPrivateKey));
  ASSERT_NE(ENCODING_FAILED, signerDER);

  // OCSP response signed by that delegated responder
  ByteString certs[] = { signerDER, ByteString() };
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID,
                         signerName, signerPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, &oneDayAfterNow, certs));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

// The CA that issued the OCSP responder cert is a sub-CA of the issuer of
// the certificate that the OCSP response is for. That sub-CA cert is included
// in the OCSP response before the OCSP responder cert.
TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder,
       good_indirect_subca_1_first)
{
  static const char* subCAName = "good_indirect_subca_1_first sub-CA";
  static const char* signerName = "good_indirect_subca_1_first OCSP signer";

  // sub-CA of root (root is the direct issuer of endEntity)
  const ByteString subCAExtensions[] = {
    CreateEncodedBasicConstraints(true, 0, ExtensionCriticality::NotCritical),
    ByteString()
  };
  ScopedSECKEYPrivateKey subCAPrivateKey;
  ByteString subCADER(CreateEncodedCertificate(
                        ++rootIssuedCount, rootName,
                        oneDayBeforeNow, oneDayAfterNow,
                        subCAName, subCAExtensions, rootPrivateKey.get(),
                        subCAPrivateKey));
  ASSERT_NE(ENCODING_FAILED, subCADER);

  // Delegated responder cert signed by that sub-CA
  const ByteString extensions[] = {
    CreateEncodedEKUExtension(OCSPSigningEKUDER,
                              ExtensionCriticality::NotCritical),
    ByteString(),
  };
  ScopedSECKEYPrivateKey signerPrivateKey;
  ByteString signerDER(CreateEncodedCertificate(
                         1, subCAName, oneDayBeforeNow, oneDayAfterNow,
                         signerName, extensions, subCAPrivateKey.get(),
                         signerPrivateKey));
  ASSERT_NE(ENCODING_FAILED, signerDER);

  // OCSP response signed by the delegated responder issued by the sub-CA
  // that is trying to impersonate the root.
  ByteString certs[] = { subCADER, signerDER, ByteString() };
  ByteString responseString(
               CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID,
                         signerName, signerPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, &oneDayAfterNow, certs));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

// The CA that issued the OCSP responder cert is a sub-CA of the issuer of
// the certificate that the OCSP response is for. That sub-CA cert is included
// in the OCSP response after the OCSP responder cert.
TEST_F(pkixocsp_VerifyEncodedResponse_DelegatedResponder,
       good_indirect_subca_1_second)
{
  static const char* subCAName = "good_indirect_subca_1_second sub-CA";
  static const char* signerName = "good_indirect_subca_1_second OCSP signer";

  // sub-CA of root (root is the direct issuer of endEntity)
  const ByteString subCAExtensions[] = {
    CreateEncodedBasicConstraints(true, 0, ExtensionCriticality::NotCritical),
    ByteString()
  };
  ScopedSECKEYPrivateKey subCAPrivateKey;
  ByteString subCADER(CreateEncodedCertificate(++rootIssuedCount, rootName,
                                               oneDayBeforeNow, oneDayAfterNow,
                                               subCAName, subCAExtensions,
                                               rootPrivateKey.get(),
                                               subCAPrivateKey));
  ASSERT_NE(ENCODING_FAILED, subCADER);

  // Delegated responder cert signed by that sub-CA
  const ByteString extensions[] = {
    CreateEncodedEKUExtension(OCSPSigningEKUDER,
                              ExtensionCriticality::NotCritical),
    ByteString()
  };
  ScopedSECKEYPrivateKey signerPrivateKey;
  ByteString signerDER(CreateEncodedCertificate(
                         1, subCAName, oneDayBeforeNow, oneDayAfterNow,
                         signerName, extensions, subCAPrivateKey.get(),
                         signerPrivateKey));
  ASSERT_NE(ENCODING_FAILED, signerDER);

  // OCSP response signed by the delegated responder issued by the sub-CA
  // that is trying to impersonate the root.
  ByteString certs[] = { signerDER, subCADER, ByteString() };
  ByteString responseString(
                 CreateEncodedOCSPSuccessfulResponse(
                         OCSPResponseContext::good, *endEntityCertID,
                         signerName, signerPrivateKey, oneDayBeforeNow,
                         oneDayBeforeNow, &oneDayAfterNow, certs));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

class pkixocsp_VerifyEncodedResponse_GetCertTrust
  : public pkixocsp_VerifyEncodedResponse_DelegatedResponder {
public:
  void SetUp()
  {
    pkixocsp_VerifyEncodedResponse_DelegatedResponder::SetUp();

    responseString =
        CreateEncodedIndirectOCSPSuccessfulResponse(
          "OCSPGetCertTrustTest Signer", OCSPResponseContext::good,
          byKey, &OCSPSigningEKUDER, &signerCertDER);
    if (responseString == ENCODING_FAILED) {
      abort();
    }
    if (response.Init(responseString.data(), responseString.length())
          != Success) {
      abort();
    }
    if (signerCertDER.length() == 0) {
      abort();
    }
  }

  class TrustDomain : public OCSPTestTrustDomain
  {
  public:
    TrustDomain()
      : certTrustLevel(TrustLevel::InheritsTrust)
    {
    }

    bool SetCertTrust(const ByteString& certDER, TrustLevel certTrustLevel)
    {
      this->certDER = certDER;
      this->certTrustLevel = certTrustLevel;
      return true;
    }
  private:
    virtual Result GetCertTrust(EndEntityOrCA endEntityOrCA,
                                const CertPolicyId&,
                                Input candidateCert,
                                /*out*/ TrustLevel& trustLevel)
    {
      EXPECT_EQ(endEntityOrCA, EndEntityOrCA::MustBeEndEntity);
      EXPECT_FALSE(certDER.empty());
      Input certDERInput;
      EXPECT_EQ(Success, certDERInput.Init(certDER.data(), certDER.length()));
      EXPECT_TRUE(InputsAreEqual(certDERInput, candidateCert));
      trustLevel = certTrustLevel;
      return Success;
    }

    ByteString certDER;
    TrustLevel certTrustLevel;
  };

  TrustDomain trustDomain;
  ByteString signerCertDER;
  ByteString responseString;
  Input response; // references data in responseString
};

TEST_F(pkixocsp_VerifyEncodedResponse_GetCertTrust, InheritTrust)
{
  ASSERT_TRUE(trustDomain.SetCertTrust(signerCertDER,
                                       TrustLevel::InheritsTrust));
  bool expired;
  ASSERT_EQ(Success,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_GetCertTrust, TrustAnchor)
{
  ASSERT_TRUE(trustDomain.SetCertTrust(signerCertDER,
                                       TrustLevel::TrustAnchor));
  bool expired;
  ASSERT_EQ(Success,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}

TEST_F(pkixocsp_VerifyEncodedResponse_GetCertTrust, ActivelyDistrusted)
{
  ASSERT_TRUE(trustDomain.SetCertTrust(signerCertDER,
                                       TrustLevel::ActivelyDistrusted));
  Input response;
  ASSERT_EQ(Success,
            response.Init(responseString.data(), responseString.length()));
  bool expired;
  ASSERT_EQ(Result::ERROR_OCSP_INVALID_SIGNING_CERT,
            VerifyEncodedOCSPResponse(trustDomain, *endEntityCertID, Now(),
                                      END_ENTITY_MAX_LIFETIME_IN_DAYS,
                                      response, expired));
  ASSERT_FALSE(expired);
}
