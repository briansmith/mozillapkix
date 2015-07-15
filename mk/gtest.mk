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

GTEST_PREFIX ?= gtest/

GTEST_CXXFLAGS += -I$(GTEST_PREFIX)include

GTEST_SRCS = \
  $(GTEST_PREFIX)src/gtest-all.cc \
  $(NULL)

GTEST_OBJS = $(addprefix $(OBJ_PREFIX), $(GTEST_SRCS:.cc=.o))

GTEST_MAIN_SRCS = \
  $(GTEST_PREFIX)src/gtest_main.cc \
  $(NULL)

GTEST_MAIN_OBJS = $(addprefix $(OBJ_PREFIX), $(GTEST_MAIN_SRCS:.cc=.o))

$(GTEST_OBJS) $(GTEST_MAIN_OBJS): CXXFLAGS += $(GTEST_CXXFLAGS) \
                                              -I$(GTEST_PREFIX) \
                                              $(NULL)
