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
OPENSSL_PREFIX = build/openssl/

include mk/gtest.mk
include mk/openssl.mk
include mk/pkix.mk

TEST_ALL_OBJS = \
  $(GTEST_MAIN_OBJS) \
  $(GTEST_OBJS) \
  $(PKIX_GTEST_OBJS) \
  $(PKIX_LIBCRYPTO_OBJS) \
  $(PKIX_LIBCRYPTO_GTEST_OBJS) \
  $(PKIX_OBJS) \
  $(NULL)

OBJS += $(TEST_ALL_OBJS)

$(EXE_PREFIX)test: LDFLAGS += -pthread
$(EXE_PREFIX)test: LDLIBS += $(OPENSSL_LDLIBS)
$(EXE_PREFIX)test: $(TEST_ALL_OBJS)
	$(CXX) $^ $(LDFLAGS) $(LDLIBS) -o $@
EXES += $(EXE_PREFIX)test

.PHONY: check
check::
	$(EXE_PREFIX)test

include mk/bottom_of_makefile.mk
