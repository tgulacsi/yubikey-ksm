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

package ykksm

import (
	"net/http"

	"github.com/tgulacsi/yubikey-val/ykval"
	"gopkg.in/inconshreveable/log15.v2"
)

var Log = log15.New()

func init() {
	Log.SetHandler(log15.DiscardHandler())
}

type DecryptHandler struct {
	KeyDB
}

func (dh DecryptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	otp := q.Get("otp")
	if otp == "" {
		Log.Error("No OTP provided")
		die("ERR No OTP provided\n")
	}

	if err := ykval.CheckOTPFormat(otp); err != nil {
		Log.Error("Invalid OTP format", "error", err)
		die("ERR Invalod OTP format\n")
	}
	i := len(otp) - ykval.TokenLen
	id, modhexCiphertext := otp[:i], otp[i:]

	key, err := dh.Get(id)
	if err != nil {
		Log.Error("Get", "id", id, "error", err)
		die("ERR Database error\n")
	}

	if key.Secret == "" {
		Log.Error("Unknown yubikey", "otp", otp)
		die("ERR Unknown yubikey\n")
	}

	ciphered := make([]byte, len(modhexCiphertext)/2)
	n, err := ykval.DecodeModhex(ciphered, modhexCiphertext)
	if err != nil {
		Log.Error("DecodeModhex", "modhex", modhexCiphertext, "error", err)
		die("ERR Corrupt OTP\n")
	}
	ciphered = ciphered[:n]
	txt := AES128ECBDecrypt(key.Secret, ciphertext)

	uid := txt[:12]
	if uid != key.InternalName {
		Log.Error("UID error", "otp", otp, "plaintext", txt, "uid", uid,
			"internal", key.InternalName)
		die("ERR Corrupt OTP\n")
	}

	if !crcOK(txt) {
		Log.Error("CRC error", "otp", otp, "plaintext", txt)
		die("ERR Corrupt OTP\n")
	}

	out := "OK counter=" + txt[14:16] + txt[12:14] +
		" low=" + txt[18:20] + txt[16:18] +
		" high=" + txt[20:22] +
		" use=" + txt[22:24]

	Log.Info("SUCCESS", "otp", otp, "plaintext", txt, "out", out)

	io.WriteString(out)
	w.WriteByte('\n')
}
