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

OPENSSL_PREFIX ?= openssl/

OPENSSL_CPPFLAGS = -I$(BUILD_PREFIX)include

OPENSSL_LDLIBS ?= -L$(BUILD_PREFIX)lib -lcrypto -lssl -ldl

OPENSSL_DIR_FLAGS ?= --openssldir=$(abspath $(BUILD_PREFIX))

OPENSSL_CONFIG_FLAGS ?= $(OPENSSL_OPTION_FLAGS) $(OPENSSL_DIR_FLAGS)

.PHONY: openssl-configure
openssl-configure: BUILD_PREFIX_ABSOLUTE =
openssl-configure:
	(cd $(OPENSSL_PREFIX) && ./config $(OPENSSL_CONFIG_FLAGS))

LIBCRYPTO_LIB = $(BUILD_PREFIX)lib/libcrypto.a
LIBSSL_LIB = $(BUILD_PREFIX)lib/libssl.a

.PHONY: openssl
openssl:
	# "make depend" doesn't work well when the compiler isn't named exactly
	# "gcc", but we don't need to execute it unless we change
	# $(OPENSSL_OPTION_FLAGS).
	# make -C $(OPENSSL_PREFIX) depend
	make -C $(OPENSSL_PREFIX)
	make -C $(OPENSSL_PREFIX) install
