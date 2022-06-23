// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauthflow

import (
	"bytes"
	"os"
	"testing"
)

func TestInteractiveFlow_IO(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		f := &InteractiveIDTokenGetter{}
		if f.GetInput() != os.Stdin {
			t.Error("expected stdin")
		}
		if f.GetOutput() != os.Stderr {
			t.Error("expected stderr")
		}
	})

	t.Run("buffer", func(t *testing.T) {
		b := new(bytes.Buffer)
		f := &InteractiveIDTokenGetter{
			Input:  b,
			Output: b,
		}
		if f.GetInput() != b {
			t.Error("expected buffer")
		}
		if f.GetOutput() != b {
			t.Error("expected buffer")
		}
	})
}
