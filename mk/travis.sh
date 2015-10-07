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

if [[ "${TRAVIS_LANGUAGE}" == "cpp" ]]; then
  if [[ "$CRYPTO_X" == "openssl" ]]; then
    make openssl-configure CC=$CC_X CXX=$CXX_X TARGET=$TARGET_X \
                           CMAKE_BUILD_TYPE=$MODE_X NO_ASM=${NO_ASM_X-} \
                           CRYPTO=$CRYPTO_X
    make openssl CC=$CC_X CXX=$CXX_X TARGET=$TARGET_X \
                 CMAKE_BUILD_TYPE=$MODE_X \ NO_ASM=${NO_ASM_X-} \
                 CRYPTO=$CRYPTO_X
  fi

  make -j2 CC=$CC_X CXX=$CXX_X TARGET=$TARGET_X CMAKE_BUILD_TYPE=$MODE_X \
           NO_ASM=${NO_ASM_X-} CRYPTO=$CRYPTO_X

  make -j2 check CC=$CC_X CXX=$CXX_X TARGET=$TARGET_X \
                 CMAKE_BUILD_TYPE=$MODE_X NO_ASM=${NO_ASM_X-} CRYPTO=$CRYPTO_X


  # Verify nothing was added to source directory during build.
  ! git clean --dry-run | grep ".*"
  if [[ $? != 0 ]]; then exit $?; fi

  make -j2 clean CC=$CC_X CXX=$CXX_X TARGET=$TARGET_X \
                 CMAKE_BUILD_TYPE=$MODE_X NO_ASM=${NO_ASM_X-} CRYPTO=$CRYPTO_X

  # TODO: Verify that |make clean| removed all files from the build directory.
  # We can't do this yet, because GTest and OpenSSL wrote stuff into build/
  # that |make clean| doesn't clean up.
  # ! find build -type f | grep ".+"
  # if [[ $? != 0 ]]; then exit $?; fi

elif [[ "${TRAVIS_LANGUAGE}" == "rust" ]]; then
  cargo version
  rustc --version

  if [[ "$MODE_X" == "RELWITHDEBINFO" ]]; then mode=--release; fi

  # TODO: Add --target $TARGET_X.

  CC=$CC_X CXX=$CXX_X cargo build -j2 ${mode-} --verbose

  CC=$CC_X CXX=$CXX_X cargo test -j2 ${mode-} --verbose

  CC=$CC_X CXX=$CXX_X cargo doc --verbose

  CC=$CC_X CXX=$CXX_X cargo clean --verbose
else
  echo Unknown TRAVIS_LANGUAGE: ${TRAVIS_LANGUAGE}
fi

echo end of mk/travis.sh
