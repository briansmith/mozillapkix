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

#ifndef mozilla_pkix_pkixlibcryptointernal_h
#define mozilla_pkix_pkixlibcryptointernal_h

#include "pkix/Input.h"
#include "pkix/Result.h"
#include <stdint.h>

namespace mozilla { namespace pkix {

// |DigestBufLibCryptoInternal| doesn't use OpenSSL's functions |SHA1|,
// |SHA256|, etc. because they've been removed from ring, and because those
// functions call |OPENSSL_cleanse|, which is unnecessary th.
template <typename CTX, typename INIT_FUNC, typename UPDATE_FUNC,
          typename FINAL_FUNC>
inline Result
DigestBufLibCryptoInternal(CTX& ctx, size_t digestLenInBytes, INIT_FUNC init,
                           UPDATE_FUNC update, FINAL_FUNC finalize, Input item,
                           uint8_t* buf, size_t bufLen)
{
  if (bufLen != digestLenInBytes) {
    return Result::FATAL_ERROR_INVALID_ARGS;
  }
  if ((init(&ctx) != 1) ||
      (update(&ctx, item.UnsafeGetData(), item.GetLength()) != 1) ||
      (finalize(buf, &ctx) != 1)) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  return Success;
}

} } // namespace mozilla::pkix

#endif // mozilla_pkix_pkixlibcryptointernal_h
