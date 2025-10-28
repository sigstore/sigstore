//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cryptoutils

import (
	"math"
	"regexp"
	"testing"
)

// expectedStringLength calculates the final string length for a given
// number of entropy bits, as per base64.RawURLEncoding rules.
func expectedStringLength(entropyInBits uint) uint {
	if entropyInBits == 0 {
		return 0
	}
	// 1. Calculate bytes needed (rounding up)
	numBytes := (entropyInBits + 7) / 8
	// 2. Calculate base64 encoded length
	// (ceil(NumBytes * 4 / 3))
	return uint(math.Ceil(float64(numBytes) * 4.0 / 3.0))
}

// TestGenerateRandomURLSafeString_Length is our primary test for "sufficient entropy".
// It validates that the *output length* correctly corresponds to the *input entropy*.
func TestGenerateRandomURLSafeString_Length(t *testing.T) {
	// t.Parallel() // Enable if tests are independent

	testCases := []struct {
		name        string
		bits        uint
		expectedLen uint
	}{
		{
			name:        "0 bits",
			bits:        0,
			expectedLen: 0,
		},
		{
			name:        "1 bit (requires 1 byte)",
			bits:        1,
			expectedLen: 2, // ceil(1 * 4 / 3) = 2
		},
		{
			name:        "8 bits (1 byte)",
			bits:        8,
			expectedLen: 2, // ceil(1 * 4 / 3) = 2
		},
		{
			name:        "128 bits (16 bytes)",
			bits:        128,
			expectedLen: 22, // ceil(16 * 4 / 3) = 22
		},
		{
			name:        "192 bits (24 bytes)",
			bits:        192,
			expectedLen: 32, // ceil(24 * 4 / 3) = 32
		},
		{
			name:        "100 bits (13 bytes)",
			bits:        100,
			expectedLen: 18, // ceil(13 * 4 / 3) = 18
		},
	}

	for _, tc := range testCases {
		// Run each case as a subtest
		t.Run(tc.name, func(t *testing.T) {
			got := GenerateRandomURLSafeString(tc.bits)

			if uint(len(got)) != tc.expectedLen {
				t.Errorf("For %d bits, expected length %d, but got %d (string: '%s')",
					tc.bits, tc.expectedLen, len(got), got)
			}

			// Also verify our helper function matches
			helperLen := expectedStringLength(tc.bits)
			if helperLen != tc.expectedLen {
				t.Errorf("Test logic error: helper function expected %d, test case expected %d",
					helperLen, tc.expectedLen)
			}
		})
	}
}

// TestGenerateRandomURLSafeString_Alphabet validates the "URL-safe" requirement.
func TestGenerateRandomURLSafeString_Alphabet(t *testing.T) {
	t.Parallel()

	// This regex matches only the 64 characters used by base64.RawURLEncoding
	// It asserts the string *only* contains these characters from start (^) to end ($).
	urlSafeRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]*$`)

	str := GenerateRandomURLSafeString(128)
	if str == "" {
		t.Fatal("Generated string is empty")
	}

	if !urlSafeRegex.MatchString(str) {
		t.Errorf("Generated string '%s' contains invalid (non-URL-safe) characters", str)
	}

	// Also check for padding
	paddingRegex := regexp.MustCompile(`=`)
	if paddingRegex.MatchString(str) {
		t.Errorf("Generated string '%s' contains padding character '='", str)
	}
}

// TestGenerateRandomURLSafeString_Uniqueness is a statistical smoke test.
// It doesn't prove randomness, but it proves the function isn't deterministic.
func TestGenerateRandomURLSafeString_Uniqueness(t *testing.T) {
	t.Parallel()

	iterations := 100
	generated := make(map[string]bool, iterations)
	entropy := uint(128) // High entropy for virtually zero collision chance

	for i := 0; i < iterations; i++ {
		str := GenerateRandomURLSafeString(entropy)
		if str == "" {
			t.Fatalf("Generated empty string on iteration %d", i)
		}

		if generated[str] {
			t.Fatalf("Collision detected! Generated the same string '%s' twice. "+
				"This is statistically impossible for 128 bits and indicates a major bug.", str)
		}
		generated[str] = true
	}
}
