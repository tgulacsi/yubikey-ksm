// Copyright (c) 2014 Tamás Gulácsi.
// Written by Simon Josefsson <simon@josefsson.org>.
// Copyright (c) 2009-2013 Yubico AB
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
	"flag"
	"net/http"

	"github.com/tgulacsi/yubikey-ksm/ykksm"
	"gopkg.in/inconshreveable/log15.v2"
)

var Log = log15.New()

func main() {
	flagHTTP := flag.String("http", ":2345", "HTTP address to listen on")
	flagDB := flag.String("db", "keys.db", "secret keys database")
	flagRecipients := flag.String("recipients", "", "GNUPG key ids to encrypt database with")
	flag.Parse()

	if *flagRecipients == "" {
		Log.Error("recipients is a must!")
		os.Exit(1)
	}

	keyDB, err := ykksm.NewKeyDB(*flagDB, strings.Split(*flagRecipients, ","))
	if err != nil {
		Log.Crit("NewKeyDB", "name", *flagDB, "recipients", *flagRecipients, "error", err)
		os.Exit(2)
	}

	http.Handle("/", ykksm.Decrypter{keyDB})

	http.ListenAndServe(*flagHTTP)
}