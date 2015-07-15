# Copyright 2015 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND BRIAN SMITH AND THE AUTHORS DISCLAIM
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BRIAN SMITH OR THE AUTHORS
# BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

PKIX_PREFIX ?= pkix/
PKIX_CXXFLAGS = -I$(PKIX_PREFIX)include

# Everything in lib except pkixnss.cpp.
PKIX_SRCS = \
  $(PKIX_PREFIX)lib/pkixbuild.cpp \
  $(PKIX_PREFIX)lib/pkixcert.cpp \
  $(PKIX_PREFIX)lib/pkixcheck.cpp \
  $(PKIX_PREFIX)lib/pkixder.cpp \
  $(PKIX_PREFIX)lib/pkixnames.cpp \
  $(PKIX_PREFIX)lib/pkixocsp.cpp \
  $(PKIX_PREFIX)lib/pkixresult.cpp \
  $(PKIX_PREFIX)lib/pkixtime.cpp \
  $(PKIX_PREFIX)lib/pkixverify.cpp \
  $(NULL)

PKIX_OBJS = $(addprefix $(OBJ_PREFIX), $(PKIX_SRCS:.cpp=.o))

$(PKIX_OBJS): CXXFLAGS += $(PKIX_CXXFLAGS)

# Everything in test/lib and test/gtest except pkixtestnss.cpp.
PKIX_GTEST_SRCS = \
  $(PKIX_PREFIX)test/gtest/pkixbuild_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixcert_extension_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixcert_signature_algorithm_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixcheck_CheckKeyUsage_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixcheck_CheckSignatureAlgorithm_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixcheck_CheckValidity_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixder_input_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixder_pki_types_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixder_universal_types_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixgtest.cpp \
  $(PKIX_PREFIX)test/gtest/pkixnames_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixocsp_CreateEncodedOCSPRequest_tests.cpp \
  $(PKIX_PREFIX)test/gtest/pkixocsp_VerifyEncodedOCSPResponse.cpp \
  $(PKIX_PREFIX)test/lib/pkixtestalg.cpp \
  $(PKIX_PREFIX)test/lib/pkixtestutil.cpp \
  $(NULL)

PKIX_GTEST_OBJS = $(addprefix $(OBJ_PREFIX), \
                    $(PKIX_GTEST_SRCS:.cpp=.o))

$(PKIX_GTEST_OBJS): CXXFLAGS += $(GTEST_CXXFLAGS) \
                                $(PKIX_CXXFLAGS) \
                                -I$(PKIX_PREFIX)lib \
                                -I$(PKIX_PREFIX)test/lib \
                                $(NULL)
