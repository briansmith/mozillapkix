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

include mk/top_of_makefile.mk

GTEST_PREFIX = build/gtest/
PKIX_PREFIX =

include mk/gtest.mk
include mk/pkix.mk

ifeq ($(CRYPTO),openssl)
OPENSSL_PREFIX = build/openssl/
include mk/openssl.mk
CRYPTO_CPPFLAGS = $(OPENSSL_CPPFLAGS)
CRYPTO_LDLIBS = -pthread $(OPENSSL_LDLIBS)
else ifeq ($(CRYPTO),ring)
RING_PREFIX = build/ring/
include $(RING_PREFIX)mk/ring.mk
OBJS += $(RING_OBJS)
LIBS += $(RING_LIB)
CRYPTO_CPPFLAGS = $(RING_CPPFLAGS)
CRYPTO_LIB = $(RING_LIB)
CRYPTO_LDLIBS = $(RING_LDLIBS)
else
$(error CRYPTO must be set to "ring" or "openssl")
endif

TEST_ALL_OBJS = \
  $(GTEST_MAIN_OBJS) \
  $(GTEST_OBJS) \
  $(PKIX_GTEST_OBJS) \
  $(PKIX_LIBCRYPTO_OBJS) \
  $(PKIX_LIBCRYPTO_GTEST_OBJS) \
  $(PKIX_OBJS) \
  $(NULL)

OBJS += $(TEST_ALL_OBJS)

$(EXE_PREFIX)test: LDLIBS += $(CRYPTO_LDLIBS)
$(EXE_PREFIX)test: $(TEST_ALL_OBJS) $(CRYPTO_LIB)
	$(CXX) $(filter-out $(CRYPTO_LIB), $^) $(LDFLAGS) $(LDLIBS) $(TARGET_ARCH) -o $@
EXES += $(EXE_PREFIX)test

.PHONY: check
check::
	$(EXE_PREFIX)test

include mk/bottom_of_makefile.mk
