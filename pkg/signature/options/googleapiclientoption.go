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

// Package options defines options for KMS clients
package options

import (
	googleoption "google.golang.org/api/option"
)

// RequestGoogleAPIClientOption implements the functional option pattern for including a Google API client option
type RequestGoogleAPIClientOption struct {
	NoOpOptionImpl
	opt googleoption.ClientOption
}

// ApplyGoogleAPIClientOption sets the specified context as the functional option
func (r RequestGoogleAPIClientOption) ApplyGoogleAPIClientOption(opt *googleoption.ClientOption) {
	*opt = r.opt
}

// WithGoogleAPIClientOption specifies that the given context should be used in RPC to external services
func WithGoogleAPIClientOption(opt googleoption.ClientOption) RequestGoogleAPIClientOption {
	return RequestGoogleAPIClientOption{opt: opt}
}
