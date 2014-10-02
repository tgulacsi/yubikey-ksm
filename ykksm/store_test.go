// Copyright (c) 2014 Tamás Gulácsi
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//   * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following
//     disclaimer in the documentation and/or other materials provided
//     with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package ykksm

import (
	"io/ioutil"
	"os"
	"testing"

	"gopkg.in/inconshreveable/log15.v2"
)

func init() {
	Log.SetHandler(log15.StderrHandler)
}

func TestEncryptedKeyDB(t *testing.T) {
	fn, err := newDbFn()
	if err != nil {
		t.Fatal(err)
	}

	st, err := NewKeyDB(fn, []string{"9ECD9AD1"})
	if err != nil {
		t.Fatalf("create store (%q): %v", fn, err)
	}

	testKeyDB(t, st)
	if err := st.Close(); err != nil {
		t.Error(err)
	}
}

func newDbFn() (string, error) {
	fh, err := ioutil.TempFile("", "keydb")
	if err != nil {
		return "", err
	}
	fn := fh.Name()
	fh.Close()
	_ = os.Remove(fn)
	return fn + ".db", nil
}

func testKeyDB(t *testing.T, st KeyDB) {
	p := Key{PublicName: "a", Secret: "secret"}
	if err := st.Set(p); err != nil {
		t.Fatalf("Set(%v): %v", p, err)
	}
	q, err := st.Get(p.PublicName)
	if err != nil {
		t.Fatalf("Get(%q): %v", p.PublicName, err)
	}
	if p != q {
		t.Errorf("p=%v != q=%v", p, q)
	}

	p.Secret += "!"
	if err = st.Set(p); err != nil {
		t.Errorf("Set2(%v): %v", p, err)
	}
	if q, err = st.Get(p.PublicName); err != nil {
		t.Errorf("Get2(%q): %v", p.PublicName, err)
	}
	if p != q {
		t.Errorf("p2=%v != q2=%v", p, q)
	}
}
