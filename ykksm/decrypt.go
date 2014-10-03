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
	"crypto/aes"
	"errors"
	"io"
	"net/http"
	"strconv"

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
		http.Error(w, "ERR No OTP provided\n", http.StatusBadRequest)
		return
	}

	if err := ykval.CheckOTPFormat(otp); err != nil {
		Log.Error("Invalid OTP format", "error", err)
		http.Error(w, "ERR Invalid OTP format\n", http.StatusBadRequest)
		return
	}
	i := len(otp) - ykval.TokenLen
	id, modhexCiphertext := otp[:i], otp[i:]

	key, err := dh.Get(id)
	if err != nil && err != io.EOF {
		Log.Error("Get", "id", id, "error", err)
		http.Error(w, "ERR Database error\n", http.StatusInternalServerError)
		return
	}

	if key.Secret == "" {
		Log.Error("Unknown yubikey", "otp", otp)
		http.Error(w, "ERR Unknown yubikey\n", http.StatusNotFound)
		return
	}

	ciphered := make([]byte, len(modhexCiphertext)/2)
	n, err := ykval.DecodeModhex(ciphered, modhexCiphertext)
	if err != nil {
		Log.Error("DecodeModhex", "modhex", modhexCiphertext, "error", err)
		http.Error(w, "ERR Corrupt OTP\n", http.StatusConflict)
		return
	}
	ciphered = ciphered[:n]
	var txtA [16]byte
	txtB := txtA[:]
	txtB, err = AES128ECBDecrypt(txtB, []byte(key.Secret), ciphered)
	if err != nil {
		Log.Error("AES128ECBDecrypt", "error", err)
		http.Error(w, "ERR Corrupt OTP\n", http.StatusConflict)
		return
	}

	txt := string(txtB)
	uid := txt[:12]
	if uid != key.InternalName {
		Log.Error("UID error", "otp", otp, "plaintext", txt, "uid", uid,
			"internal", key.InternalName)
		http.Error(w, "ERR Corrupt OTP\n", http.StatusConflict)
		return
	}

	if !crcOK(txtB) {
		Log.Error("CRC error", "otp", otp, "plaintext", txt)
		http.Error(w, "ERR Corrupt OTP\n", http.StatusConflict)
		return
	}

	out := "OK counter=" + txt[14:16] + txt[12:14] +
		" low=" + txt[18:20] + txt[16:18] +
		" high=" + txt[20:22] +
		" use=" + txt[22:24]

	Log.Info("SUCCESS", "otp", otp, "plaintext", txt, "out", out)

	w.Header().Set("Content-Length", strconv.Itoa(len(out)+1))
	io.WriteString(w, out+"\n")
}

func crcOK(data []byte) bool {
	return CalculateCRC(data) == 0xf0b8
}

// CalculateCRC calculates a 16-bit CRC or the given data.
func CalculateCRC(data []byte) uint16 {
	crc := uint16(0xffff)
	for _, b := range data {
		crc ^= uint16(b)
		for j := 0; j < 8; j++ {
			n := crc & 1
			crc = crc >> 1
			if n != 0 {
				crc ^= 0x8408
			}
		}
	}
	return crc
}

// AES128ECBDecrypt decrypts txt encrypted with key in AES128 ECB mode.
//
// ECB mode is insecure!!! See https://code.google.com/p/go/issues/detail?id=5597
func AES128ECBDecrypt(dst, key, txt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		Log.Crit("aes.NewCipher", "error", err)
		return dst, err
	}
	bs := block.BlockSize()
	ts := len(txt)
	if ts%bs != 0 {
		Log.Crit("Need a multiple of the blocksize", "blocksize", bs, "textsize", ts)
		return dst, errors.New("plaintext must be a multiple of blocksize")
	}

	if cap(dst) >= ts {
		dst = dst[:ts]
	} else {
		dst = make([]byte, ts)
	}
	ciphertext := dst
	for len(txt) > 0 {
		block.Encrypt(ciphertext, txt)
		txt = txt[bs:]
		ciphertext = ciphertext[bs:]
	}
	return dst, nil
}
