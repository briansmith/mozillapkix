#!/usr/bin/env bash
#
# Copyright 2015 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -eux -o pipefail
IFS=$'\n\t'

printenv
$CC_X --version
$CXX_X --version
make --version

if [[ "$CRYPTO_X" == "ring" ]]; then
  git clone -b wip --depth 1 --single-branch \
            https://github.com/briansmith/ring build/ring
elif [[ "$CRYPTO_X" == "openssl" ]]; then
  git clone -b OpenSSL_1_0_2-stable --depth 1 --single-branch \
            https://github.com/openssl/openssl build/openssl;
else
  echo CRYPTO_X="$CRYPTO_X" is not a valid value.
  exit 1
fi

git clone -b master --depth 1 --single-branch \
          https://github.com/briansmith/googletest build/gtest
