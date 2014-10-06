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

package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tgulacsi/go/cmdmain"
	"github.com/tgulacsi/yubikey-ksm/ykksm"
)

type export struct {
	csv bool
}

func (m export) Usage() {
	io.WriteString(os.Stderr, usagePrefix+`export [-csv] [outfile]`)
}
func (m export) Examples() []string {
	return []string{
		"",
		"-csv /dest/file.csv",
	}
}
func (m export) Describe() string {
	return `exports KSM database in JSON/CSV format. If the given filename ends
	with .json, then JSON output will be generated, otherwise CSV.`
}
func (m export) RunCommand(args []string) error {
	dest := ""
	if len(args) > 0 {
		dest = args[0]
	}
	db := mustKeyDB(true)
	defer db.Close()
	return doExport(db, dest)
}

type imprt struct{}

func (m imprt) Usage() {
	io.WriteString(os.Stderr, usagePrefix+`import [inputfile]`)
}
func (m imprt) Examples() []string {
	return []string{"imprt.csv"}
}
func (m imprt) Describe() string {
	return `imports KSM database from JSON/CSV file. Sniffs the format from the data.`
}
func (m imprt) RunCommand(args []string) error {
	dest := ""
	if len(args) > 0 {
		dest = args[0]
	}
	db := mustKeyDB(false)
	defer db.Close()
	return doImport(db, dest)
}

func init() {
	cmdmain.RegisterCommand("export", func(Flags *flag.FlagSet) cmdmain.CommandRunner {
		m := &export{}
		Flags.BoolVar(&m.csv, "csv", false, "CSV output? (The default is JSON)")
		return m
	})
	cmdmain.RegisterCommand("import", func(Flags *flag.FlagSet) cmdmain.CommandRunner {
		return &imprt{}
	})
}

func doExport(db ykksm.KeyDB, dest string) error {
	n := int64(0)
	it := db.Iterate()
	var w *bufio.Writer
	if dest == "" || dest == "-" {
		w = bufio.NewWriter(os.Stdout)
	} else {
		f, err := os.Create(dest)
		if err != nil {
			Log.Crit("create", "file", dest, "error", err)
			return err
		}
		defer func() {
			if err := f.Close(); err != nil {
				Log.Error("Close", "file", f.Name(), "error", err)
			}
		}()
		w = bufio.NewWriter(f)
	}
	defer func() {
		if err := w.Flush(); err != nil {
			Log.Error("Flush", "error", err)
		}
	}()

	print := func(k ykksm.Key) {
		io.WriteString(w, `"`+k.PublicName+`","`+k.Secret+`","`+k.InternalName+`"`+"\n")
	}
	if dest == "" || strings.HasSuffix(dest, ".json") {
		e := json.NewEncoder(w)
		print = func(k ykksm.Key) {
			if err := e.Encode(k); err != nil {
				Log.Error("marshal", "k", k, "error", err)
			}
		}
	}
	for {
		key, err := it.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			Log.Error("Iterate", "error", err)
			continue
		}
		print(key)
		n++
	}
	Log.Info(fmt.Sprintf("Successfully exported %d records.", n))
	return nil
}

func doImport(db ykksm.KeyDB, src string) error {
	n := int64(0)
	var r *bufio.Reader
	if src == "" || src == "-" {
		r = bufio.NewReader(os.Stdin)
	} else {
		f, err := os.Open(src)
		if err != nil {
			Log.Crit("open", "file", src, "error", err)
			return err
		}
		defer f.Close()
		r = bufio.NewReader(f)
	}
	defer func() {
		if err := db.Close(); err != nil {
			Log.Error("db.Close", "error", err)
		}
	}()

	i := r.Buffered()
	if i < 10 {
		i = 10
	}
	b, err := r.Peek(i)
	if err != nil {
		Log.Error("Peek", "error", err)
		return err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		Log.Warn("empty input")
		return err
	}

	errLineTooShort := errors.New("line too short")
	var load func() (ykksm.Key, error)
	if b[0] == '{' {
		d := json.NewDecoder(r)
		load = func() (ykksm.Key, error) {
			var k ykksm.Key
			err := d.Decode(&k)
			return k, err
		}
	} else {
		rdr := csv.NewReader(r)
		load = func() (ykksm.Key, error) {
			var k ykksm.Key
			rec, err := rdr.Read()
			if err != nil {
				if err == io.EOF {
					return k, io.EOF
				}
				return k, err
			}
			k.PublicName, k.Secret, k.InternalName = rec[0], rec[1], rec[2]
			return k, nil
		}
	}
Loop:
	for {
		k, err := load()
		if err != nil {
			switch err {
			case io.EOF:
				break Loop
			case errLineTooShort:
				Log.Warn(err.Error())
				continue
			}
			Log.Error("load", "error", err)
			break Loop
		}
		Log.Info("load", "k", k)
		if err := db.Set(k); err != nil {
			Log.Error("Set", "k", k, "error", err)
			continue
		}
	}
	Log.Info(fmt.Sprintf("Successfully imported %d records.", n))
	return nil
}
