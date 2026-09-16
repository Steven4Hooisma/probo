// Copyright (c) 2026 Probo Inc <hello@probo.com>.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package coredata

import (
	"encoding"
	"fmt"
)

// DeviceSource records where a device row came from, which determines what the
// rest of the row can be trusted to contain. An AGENT device is enrolled by the
// Probo agent and reports its own hardware UUID, hostname, OS and posture; an
// externally sourced device is mirrored from an inventory system and carries
// only what that system publishes, so the agent-populated columns stay NULL.
type DeviceSource string

const (
	DeviceSourceAgent                DeviceSource = "AGENT"
	DeviceSourceAppleBusinessManager DeviceSource = "APPLE_BUSINESS_MANAGER"
)

var (
	_ fmt.Stringer             = DeviceSource("")
	_ encoding.TextMarshaler   = DeviceSource("")
	_ encoding.TextUnmarshaler = (*DeviceSource)(nil)
)

func DeviceSources() []DeviceSource {
	return []DeviceSource{
		DeviceSourceAgent,
		DeviceSourceAppleBusinessManager,
	}
}

func (v DeviceSource) IsValid() bool {
	switch v {
	case
		DeviceSourceAgent,
		DeviceSourceAppleBusinessManager:
		return true
	}

	return false
}

// IsExternal reports whether the device is mirrored from a third-party
// inventory system rather than enrolled by the agent. External devices are
// reconciled by the device sync worker and must never be mutated by the
// agent-facing endpoints.
func (v DeviceSource) IsExternal() bool {
	return v != DeviceSourceAgent
}

func (v DeviceSource) String() string {
	return string(v)
}

func (v DeviceSource) MarshalText() ([]byte, error) {
	return []byte(v.String()), nil
}

func (v *DeviceSource) UnmarshalText(text []byte) error {
	val := DeviceSource(text)
	if !val.IsValid() {
		return fmt.Errorf("invalid DeviceSource value: %q", string(text))
	}

	*v = val

	return nil
}
