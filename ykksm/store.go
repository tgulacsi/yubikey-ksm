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
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tgulacsi/trousseau"
)

var ErrNotFound = errors.New("not found")
var ErrReadOnly = errors.New("DB is read-only")

type Key struct {
	PublicName   string `ql:"uindex xPublicName"`
	Secret       string
	InternalName string
}

type KeyDB interface {
	Get(string) (Key, error)
	Set(Key) error
	Close() error
	Iterate() KeyDBIterator
}

type KeyDBIterator interface {
	Next() (Key, error)
}

// NewKeyDB returns a new KeyDB, implemented with github.com/oleiade/trousseau.
// If passphrase is "", we prompt for the passphrase.
func NewKeyDB(name string, recipients []string, readOnly bool) (KeyDB, error) {
	tr, err := trousseau.OpenTrousseau(name)
	if err == nil {
		store, err := tr.Decrypt()
		if err != nil {
			return nil, err
		}
		if readOnly {
			return trDB{Path: name, Store: store}, nil
		}
		return trDB{Path: name, Tr: tr, Store: store}, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	tr = &trousseau.Trousseau{
		CryptoType:      trousseau.ASYMMETRIC_ENCRYPTION,
		CryptoAlgorithm: trousseau.GPG_ENCRYPTION,
	}
	now := time.Now().Format(time.RFC3339)
	store := trousseau.NewStore(trousseau.Meta{
		CreatedAt:        now,
		LastModifiedAt:   now,
		Recipients:       recipients,
		TrousseauVersion: trousseau.TROUSSEAU_VERSION,
	})
	if readOnly {
		return trDB{Path: name, Store: store}, nil
	}
	return trDB{Path: name, Tr: tr, Store: store}, nil
}

type trDB struct {
	Path  string
	Tr    *trousseau.Trousseau
	Store *trousseau.Store
}

func (db trDB) Get(devID string) (Key, error) {
	v, err := db.Store.Data.Get(devID)
	if err != nil {
		return Key{}, err
	}
	m := v.(map[string]interface{})
	return Key{
		PublicName:   m["PublicName"].(string),
		Secret:       m["Secret"].(string),
		InternalName: m["InternalName"].(string),
	}, nil
}

func (db trDB) Set(p Key) error {
	if db.Tr == nil {
		return ErrReadOnly
	}
	db.Store.Data.Set(p.PublicName, p)
	return nil
}

func (db trDB) Flush() error {
	if db.Tr == nil {
		Log.Warn("Flush on a read-only DB")
		return nil
	}
	if err := db.Tr.Encrypt(db.Store); err != nil {
		return fmt.Errorf("Flush: Encrypt: %v", err)
	}
	return db.Tr.Write(db.Path)
}

func (db trDB) Close() error {
	return db.Flush()
}

func (db trDB) Iterate() KeyDBIterator {
	return &trDBIterator{db: &db, keys: db.Store.Data.Keys()}
}

type trDBIterator struct {
	db   *trDB
	keys []string
	pos  int
}

func (it *trDBIterator) Next() (Key, error) {
	if len(it.keys) <= it.pos {
		return Key{}, io.EOF
	}
	key, err := it.db.Get(it.keys[it.pos])
	it.pos++
	return key, err
}
