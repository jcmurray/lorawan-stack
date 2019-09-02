// Copyright © 2019 The Things Network Foundation, The Things Industries B.V.
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

package auth

import (
	"testing"

	"github.com/smartystreets/assertions"
	"go.thethings.network/lorawan-stack/pkg/util/test"
	"go.thethings.network/lorawan-stack/pkg/util/test/assertions/should"
)

func TestHash(t *testing.T) {
	a := assertions.New(t)

	ctx := test.Context()

	plain := "secret"

	p, err := Hash(ctx, plain)
	a.So(err, should.BeNil)

	{
		ok, err := Validate(p, plain)
		a.So(err, should.BeNil)
		a.So(ok, should.BeTrue)
	}

	{
		ok, err := Validate(p, "somethingelse")
		a.So(err, should.BeNil)
		a.So(ok, should.BeFalse)
	}

	{
		ok, err := Validate("foo", "somethingelse")
		a.So(err, should.NotBeNil)
		a.So(ok, should.BeFalse)
	}

	{
		ok, err := Validate("LOL$foo", "somethingelse")
		a.So(err, should.NotBeNil)
		a.So(ok, should.BeFalse)
	}

	{
		ok, err := Validate("PBKDF2$foo", "somethingelse")
		a.So(err, should.NotBeNil)
		a.So(ok, should.BeFalse)
	}
}

func TestLegacy(t *testing.T) {
	a := assertions.New(t)

	// this is a pair generated by django
	ok, err := Validate("pbkdf2$sha256$30000$salt$4v3K66vbKbwv3vnwnf32hdzoK8O03GOiBcWFNHul9bo", "secret")
	a.So(err, should.BeNil)
	a.So(ok, should.BeTrue)
}