// Copyright 2021 The Sigstore Authors.
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

package option

import "context"

// RequestContext is an option which designates a request context, as required by some Signer, Verifier, or PublicKeyProvider implementations.
type RequestContext struct {
	NoOpOptionImpl
	ctx context.Context
}

// ApplyContext sets the specified Context, implementing the RPCOption interface.
func (c RequestContext) ApplyContext(ctx *context.Context) {
	*ctx = c.ctx
}

// WithContext returns an option which designates the request context.
func WithContext(ctx context.Context) RequestContext {
	return RequestContext{ctx: ctx}
}
