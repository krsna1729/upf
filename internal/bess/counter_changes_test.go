// SPDX-License-Identifier: BSD-3-Clause
package bess

import "testing"

func TestMalformedActivityCannotReturnAnAcknowledgableSnapshot(t *testing.T) {
	for name, raw := range map[string][]byte{
		"missing sequence":    {0x12, 0x01, 0x01},
		"truncated sequence":  {0x08, 0x80},
		"truncated packed id": {0x08, 0x01, 0x12, 0x01, 0x80},
		"truncated next page": {0x08, 0x01, 0x12, 0x01, 0x01, 0x18, 0x80},
	} {
		t.Run(name, func(t *testing.T) {
			page, err := appendChanges(nil, raw)
			if err == nil || page.Sequence != 0 || len(page.ActionIDs) != 0 {
				t.Fatalf("malformed activity could be scheduled/acknowledged: %+v, %v", page, err)
			}
		})
	}
}
