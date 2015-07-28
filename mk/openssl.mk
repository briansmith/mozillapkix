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

ifeq ($(OPENSSL_CONFIG_BASE),)
ifeq ($(ARCH),x86)
OPENSSL_CONFIG_BASE = linux-elf
else ifeq ($(ARCH),x86_64)
OPENSSL_CONFIG_BASE = linux-x86_64
else
$(error OPENSSL_CONFIG_BASE not defined and unsupported ARCH: $(ARCH))
endif
endif
# Although we don't use CMake, we use a variable RELWITHDEBINFO with
# similar semantics to the CMake variable of that name.
ifeq ($(CMAKE_BUILD_TYPE),DEBUG)
OPENSSL_CONFIG_BASE_PREFIX = debug-
endif

# TODO: OpenSSL's debug-linux-elf configuration tries to link with -lefence,
#       which I haven't figured out how to install in Travis CI, so just use
#       the normal (non-debug) configuration in that case, for now.
ifeq ($(OPENSSL_CONFIG_BASE_PREFIX)$(OPENSSL_CONFIG_BASE),debug-linux-elf)
OPENSSL_CONFIG_BASE_PREFIX =
endif

OPENSSL_CONFIG_FLAGS ?= $(OPENSSL_CONFIG_BASE_PREFIX)$(OPENSSL_CONFIG_BASE) \
                        $(OPENSSL_OPTION_FLAGS) \
                        $(OPENSSL_DIR_FLAGS) \
                        $(ARCH_FLAGS) \
                        $(NULL)

.PHONY: openssl-configure
openssl-configure: BUILD_PREFIX_ABSOLUTE =
openssl-configure:
	(cd $(OPENSSL_PREFIX) && ./Configure $(OPENSSL_CONFIG_FLAGS))

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
