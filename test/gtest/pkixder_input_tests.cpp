/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This code is made available to you under your choice of the following sets
 * of licensing terms:
 */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
/* Copyright 2013 Mozilla Contributors
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

#include <functional>
#include <vector>
#include "pkixgtest.h"

#include "pkixder.h"

using namespace mozilla::pkix;
using namespace mozilla::pkix::der;

namespace {

class pkixder_input_tests : public ::testing::Test { };

const uint8_t DER_SEQUENCE_OF_INT8[] = {
  0x30,                       // SEQUENCE
  0x09,                       // length
  0x02, 0x01, 0x01,           // INTEGER length 1 value 0x01
  0x02, 0x01, 0x02,           // INTEGER length 1 value 0x02
  0x02, 0x01, 0x03            // INTEGER length 1 value 0x03
};

static const Input EMPTY_INPUT;

TEST_F(pkixder_input_tests, InputInit)
{
  Input buf;
  ASSERT_EQ(Input::OK,
            buf.Init(DER_SEQUENCE_OF_INT8, sizeof DER_SEQUENCE_OF_INT8));
}

TEST_F(pkixder_input_tests, InputInitWithNullPointerOrZeroLength)
{
  Input buf;
  ASSERT_EQ(Input::BAD, buf.Init(nullptr, 0));

  ASSERT_EQ(Input::BAD, buf.Init(nullptr, 100));

  // Though it seems odd to initialize with zero-length and non-null ptr, this
  // is working as intended. The Reader class was intended to protect against
  // buffer overflows, and there's no risk with the current behavior. See bug
  // 1000354.
  ASSERT_EQ(Input::OK, buf.Init((const uint8_t*) "hello", 0));
  ASSERT_TRUE(buf.GetLength() == 0);
}

TEST_F(pkixder_input_tests, InputInitWithLargeData)
{
  Input buf;
  // Data argument length does not matter, it is not touched, just
  // needs to be non-null
  ASSERT_EQ(Input::BAD, buf.Init((const uint8_t*) "", 0xffff+1));

  ASSERT_EQ(Input::OK, buf.Init((const uint8_t*) "", 0xffff));
}

TEST_F(pkixder_input_tests, InputInitMultipleTimes)
{
  Input buf;

  ASSERT_EQ(Input::OK,
            buf.Init(DER_SEQUENCE_OF_INT8, sizeof DER_SEQUENCE_OF_INT8));

  ASSERT_EQ(Input::BAD,
            buf.Init(DER_SEQUENCE_OF_INT8, sizeof DER_SEQUENCE_OF_INT8));
}

TEST_F(pkixder_input_tests, PeekWithinBounds)
{
  const uint8_t der[] = { 0x11, 0x11 };
  Input buf(der);
  Reader input(buf);
  ASSERT_TRUE(input.Peek(0x11));
  ASSERT_FALSE(input.Peek(0x22));
}

TEST_F(pkixder_input_tests, PeekPastBounds)
{
  const uint8_t der[] = { 0x11, 0x22 };
  Input buf;
  ASSERT_EQ(Input::OK, buf.Init(der, 1));
  Reader input(buf);

  uint8_t readByte;
  ASSERT_EQ(Input::OK, input.Read(readByte));
  ASSERT_EQ(0x11, readByte);
  ASSERT_FALSE(input.Peek(0x22));
}

TEST_F(pkixder_input_tests, ReadByte)
{
  const uint8_t der[] = { 0x11, 0x22 };
  Input buf(der);
  Reader input(buf);

  uint8_t readByte1;
  ASSERT_EQ(Input::OK, input.Read(readByte1));
  ASSERT_EQ(0x11, readByte1);

  uint8_t readByte2;
  ASSERT_EQ(Input::OK, input.Read(readByte2));
  ASSERT_EQ(0x22, readByte2);
}

TEST_F(pkixder_input_tests, ReadBytePastEnd)
{
  const uint8_t der[] = { 0x11, 0x22 };
  Input buf;
  ASSERT_EQ(Input::OK, buf.Init(der, 1));
  Reader input(buf);

  uint8_t readByte1 = 0;
  ASSERT_EQ(Input::OK, input.Read(readByte1));
  ASSERT_EQ(0x11, readByte1);

  uint8_t readByte2 = 0;
  ASSERT_EQ(Input::BAD, input.Read(readByte2));
  ASSERT_NE(0x22, readByte2);
}

TEST_F(pkixder_input_tests, ReadByteWrapAroundPointer)
{
  // The original implementation of our buffer read overflow checks was
  // susceptible to integer overflows which could make the checks ineffective.
  // This attempts to verify that we've fixed that. Unfortunately, decrementing
  // a null pointer is undefined behavior according to the C++ language spec.,
  // but this should catch the problem on at least some compilers, if not all of
  // them.
  const uint8_t* der = nullptr;
  --der;
  Input buf;
  ASSERT_EQ(Input::OK, buf.Init(der, 0));
  Reader input(buf);

  uint8_t b;
  ASSERT_EQ(Input::BAD, input.Read(b));
}

TEST_F(pkixder_input_tests, ReadWord)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  uint16_t readWord1 = 0;
  ASSERT_EQ(Input::OK, input.Read(readWord1));
  ASSERT_EQ(0x1122, readWord1);

  uint16_t readWord2 = 0;
  ASSERT_EQ(Input::OK, input.Read(readWord2));
  ASSERT_EQ(0x3344, readWord2);
}

TEST_F(pkixder_input_tests, ReadWordPastEnd)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf;
  ASSERT_EQ(Input::OK, buf.Init(der, 2)); // Initialize with too-short length
  Reader input(buf);

  uint16_t readWord1 = 0;
  ASSERT_EQ(Input::OK, input.Read(readWord1));
  ASSERT_EQ(0x1122, readWord1);

  uint16_t readWord2 = 0;
  ASSERT_EQ(Input::BAD, input.Read(readWord2));
  ASSERT_NE(0x3344, readWord2);
}

TEST_F(pkixder_input_tests, ReadWordWithInsufficentData)
{
  const uint8_t der[] = { 0x11, 0x22 };
  Input buf;
  ASSERT_EQ(Input::OK, buf.Init(der, 1));
  Reader input(buf);

  uint16_t readWord1 = 0;
  ASSERT_EQ(Input::BAD, input.Read(readWord1));
  ASSERT_NE(0x1122, readWord1);
}

TEST_F(pkixder_input_tests, ReadWordWrapAroundPointer)
{
  // The original implementation of our buffer read overflow checks was
  // susceptible to integer overflows which could make the checks ineffective.
  // This attempts to verify that we've fixed that. Unfortunately, decrementing
  // a null pointer is undefined behavior according to the C++ language spec.,
  // but this should catch the problem on at least some compilers, if not all of
  // them.
  const uint8_t* der = nullptr;
  --der;
  Input buf;
  ASSERT_EQ(Input::OK, buf.Init(der, 0));
  Reader input(buf);
  uint16_t b;
  ASSERT_EQ(Input::BAD, input.Read(b));
}

TEST_F(pkixder_input_tests, Skip)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  ASSERT_EQ(Input::OK, input.Skip(1));

  uint8_t readByte1 = 0;
  ASSERT_EQ(Input::OK, input.Read(readByte1));
  ASSERT_EQ(0x22, readByte1);

  ASSERT_EQ(Input::OK, input.Skip(1));

  uint8_t readByte2 = 0;
  ASSERT_EQ(Input::OK, input.Read(readByte2));
  ASSERT_EQ(0x44, readByte2);
}

TEST_F(pkixder_input_tests, Skip_ToEnd)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);
  ASSERT_EQ(Input::OK, input.Skip(sizeof der));
  ASSERT_TRUE(input.AtEnd());
}

TEST_F(pkixder_input_tests, Skip_PastEnd)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  ASSERT_EQ(Input::BAD, input.Skip(sizeof der + 1));
}

TEST_F(pkixder_input_tests, Skip_ToNewInput)
{
  const uint8_t der[] = { 0x01, 0x02, 0x03, 0x04 };
  Input buf(der);
  Reader input(buf);

  Reader skippedInput;
  ASSERT_EQ(Input::OK, input.Skip(3, skippedInput));

  uint8_t readByte1 = 0;
  ASSERT_EQ(Input::OK, input.Read(readByte1));
  ASSERT_EQ(0x04, readByte1);

  ASSERT_TRUE(input.AtEnd());

  // Reader has no Remaining() or Length() so we simply read the bytes
  // and then expect to be at the end.

  for (uint8_t i = 1; i <= 3; ++i) {
    uint8_t readByte = 0;
    ASSERT_EQ(Input::OK, skippedInput.Read(readByte));
    ASSERT_EQ(i, readByte);
  }

  ASSERT_TRUE(skippedInput.AtEnd());
}

TEST_F(pkixder_input_tests, Skip_ToNewInputPastEnd)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  Reader skippedInput;
  ASSERT_EQ(Input::BAD, input.Skip(sizeof der * 2, skippedInput));
}

TEST_F(pkixder_input_tests, Skip_ToInput)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  const uint8_t expectedItemData[] = { 0x11, 0x22, 0x33 };

  Input item;
  ASSERT_EQ(Input::OK, input.Skip(sizeof expectedItemData, item));

  Input expected(expectedItemData);
  ASSERT_TRUE(InputsAreEqual(expected, item));
}

TEST_F(pkixder_input_tests, Skip_WrapAroundPointer)
{
  // The original implementation of our buffer read overflow checks was
  // susceptible to integer overflows which could make the checks ineffective.
  // This attempts to verify that we've fixed that. Unfortunately, decrementing
  // a null pointer is undefined behavior according to the C++ language spec.,
  // but this should catch the problem on at least some compilers, if not all of
  // them.
  const uint8_t* der = nullptr;
  --der;
  Input buf;
  ASSERT_EQ(Input::OK, buf.Init(der, 0));
  Reader input(buf);
  ASSERT_EQ(Input::BAD, input.Skip(1));
}

TEST_F(pkixder_input_tests, Skip_ToInputPastEnd)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  Input skipped;
  ASSERT_EQ(Input::BAD, input.Skip(sizeof der + 1, skipped));
}

TEST_F(pkixder_input_tests, SkipToEnd_ToInput)
{
  static const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  Input skipped;
  ASSERT_EQ(Input::OK, input.SkipToEnd(skipped));
}

TEST_F(pkixder_input_tests, SkipToEnd_ToInput_InputAlreadyInited)
{
  static const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  static const uint8_t initialValue[] = { 0x01, 0x02, 0x03 };
  Input x(initialValue);
  // Fails because skipped was already initialized once, and Inputs are not
  // allowed to be Init()d multiple times.
  ASSERT_EQ(Input::BAD, input.SkipToEnd(x));
  ASSERT_TRUE(InputsAreEqual(x, Input(initialValue)));
}

TEST_F(pkixder_input_tests, AtEndOnUnInitializedInput)
{
  Reader input;
  ASSERT_TRUE(input.AtEnd());
}

TEST_F(pkixder_input_tests, AtEndAtBeginning)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);
  ASSERT_FALSE(input.AtEnd());
}

TEST_F(pkixder_input_tests, AtEndAtEnd)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);
  ASSERT_EQ(Input::OK, input.Skip(sizeof der));
  ASSERT_TRUE(input.AtEnd());
}

TEST_F(pkixder_input_tests, MarkAndGetInput)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  Reader::Mark mark = input.GetMark();

  const uint8_t expectedItemData[] = { 0x11, 0x22, 0x33 };

  ASSERT_EQ(Input::OK, input.Skip(sizeof expectedItemData));

  Input item;
  ASSERT_EQ(Input::OK, input.GetInput(mark, item));
  Input expected(expectedItemData);
  ASSERT_TRUE(InputsAreEqual(expected, item));
}

// Cannot run this test on debug builds because of the NotReached
#ifdef NDEBUG
TEST_F(pkixder_input_tests, MarkAndGetInputDifferentInput)
{
  const uint8_t der[] = { 0x11, 0x22, 0x33, 0x44 };
  Input buf(der);
  Reader input(buf);

  Reader another;
  Reader::Mark mark = another.GetMark();

  ASSERT_EQ(Input::OK, input.Skip(3));

  Input item;
  ASSERT_EQ(Input::BAD, input.GetInput(mark, item));
}
#endif

TEST_F(pkixder_input_tests, MatchRestAtEnd)
{
  static const uint8_t der[1] = { };
  Input buf;
  ASSERT_EQ(Input::OK, buf.Init(der, 0));
  Reader input(buf);
  ASSERT_TRUE(input.AtEnd());
  static const uint8_t toMatch[] = { 1 };
  ASSERT_FALSE(input.MatchRest(toMatch));
}

TEST_F(pkixder_input_tests, MatchRest1Match)
{
  static const uint8_t der[] = { 1 };
  Input buf(der);
  Reader input(buf);
  ASSERT_FALSE(input.AtEnd());
  ASSERT_TRUE(input.MatchRest(der));
}

TEST_F(pkixder_input_tests, MatchRest1Mismatch)
{
  static const uint8_t der[] = { 1 };
  Input buf(der);
  Reader input(buf);
  static const uint8_t toMatch[] = { 2 };
  ASSERT_FALSE(input.MatchRest(toMatch));
  ASSERT_FALSE(input.AtEnd());
}

TEST_F(pkixder_input_tests, MatchRest2WithTrailingByte)
{
  static const uint8_t der[] = { 1, 2, 3 };
  Input buf(der);
  Reader input(buf);
  static const uint8_t toMatch[] = { 1, 2 };
  ASSERT_FALSE(input.MatchRest(toMatch));
}

TEST_F(pkixder_input_tests, MatchRest2Mismatch)
{
  static const uint8_t der[] = { 1, 2, 3 };
  Input buf(der);
  Reader input(buf);
  static const uint8_t toMatchMismatch[] = { 1, 3 };
  ASSERT_FALSE(input.MatchRest(toMatchMismatch));
  ASSERT_TRUE(input.MatchRest(der));
}

} // unnamed namespace
