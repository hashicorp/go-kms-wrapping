// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// Sha256Sum computes SHA256 message digest. Options supported: WithHexEncoding
// (which is compatible/comparable with GNU sha256sum's output)
func Sha256Sum(ctx context.Context, r io.Reader, opt ...wrapping.Option) ([]byte, error) {
	const op = "crypto.Sha256Sum"
	switch {
	case isNil(r):
		return nil, fmt.Errorf("%s: missing reader: %w", op, wrapping.ErrInvalidParameter)
	}

	hasher := sha256.New()

	if _, err := io.Copy(hasher, r); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	hash := hasher.Sum(nil)
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if opts.WithHexEncoding {
		encodedHex := hex.EncodeToString(hash[:])
		return []byte(encodedHex), nil
	}
	return hash, nil
}

// Sha256SumWriter provides multi-writer which will be used to write to a
// hash and produce a sum.  It implements io.WriterCloser and io.StringWriter.
type Sha256SumWriter struct {
	hash hash.Hash
	tee  io.Writer
}

// NewSha256SumWriter creates a new Sha256SumWriter
func NewSha256SumWriter(ctx context.Context, w io.Writer) (*Sha256SumWriter, error) {
	const op = "crypto.NewSha256SumWriter"
	switch {
	case isNil(w):
		return nil, fmt.Errorf("%s: missing writer: %w", op, wrapping.ErrInvalidParameter)
	}
	h := sha256.New()
	tee := io.MultiWriter(w, h)
	return &Sha256SumWriter{
		hash: h,
		tee:  tee,
	}, nil
}

// Write will write the bytes to the hash. Implements the required io.Writer
// func.
func (w *Sha256SumWriter) Write(b []byte) (int, error) {
	const op = "crypto.(Sha256SumWriter).Write"
	n, err := w.tee.Write(b)
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// WriteString will write the string to hash.
func (w *Sha256SumWriter) WriteString(s string) (int, error) {
	const op = "crypto.(Sha256SumWriter).WriteString"
	n, err := w.Write([]byte(s))
	if err != nil {
		return n, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// Close checks to see if the Sha256SumWriter implements the optional io.Closer
// and if so, then Close() is called; otherwise this is a noop
func (w *Sha256SumWriter) Close() error {
	const op = "crypto.(Sha256SumWriter).WriteString"
	var i interface{} = w.tee
	if v, ok := i.(io.Closer); ok {
		if err := v.Close(); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}

// Sum will sum the hash.  Options supported: WithHexEncoding
func (w *Sha256SumWriter) Sum(_ context.Context, opt ...wrapping.Option) ([]byte, error) {
	const op = "crypto.(Sha256SumWriter).Sum"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	h := w.hash.Sum(nil)
	switch {
	case opts.WithHexEncoding:
		encodedHex := hex.EncodeToString(h[:])
		return []byte(encodedHex), nil
	default:
		return h, nil
	}
}
