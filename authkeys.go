package hg

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type AuthorizedKeys []AuthorizedKey

type AuthorizedKey struct {
	ssh.PublicKey
	Options []string
	Comment string
}

func (a AuthorizedKeys) AppendText(b []byte) ([]byte, error) {
	buf := bytes.NewBuffer(b)

	for _, akey := range a {
		for i, opt := range akey.Options {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(opt)
		}
		if len(akey.Options) > 0 {
			buf.WriteByte(' ')
		}

		buf.WriteString(akey.Type())
		buf.WriteByte(' ')

		enc := base64.NewEncoder(base64.StdEncoding, buf)
		enc.Write(akey.Marshal())
		enc.Close()

		if len(akey.Comment) > 0 {
			buf.WriteByte(' ')
			buf.WriteString(akey.Comment)
		}

		buf.WriteByte('\n')
	}

	return buf.Bytes(), nil
}

func (a AuthorizedKeys) MarshalText() ([]byte, error) {
	return a.AppendText(nil)
}

func (a *AuthorizedKeys) UnmarshalText(b []byte) error {
	var keys []AuthorizedKey
	for i := 1; len(b) > 0; i++ {
		var line []byte
		if j := bytes.IndexByte(line, '\n'); j >= 0 {
			line, b = b[:j], b[j+1:]
		} else {
			line, b = b, nil
		}

		b = bytes.TrimSpace(b)
		if len(b) == 0 || b[0] == '#' {
			continue
		}

		out, comment, options, rest, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return fmt.Errorf("hg: line %d: %w", i, err)
		}
		if len(rest) > 0 {
			return fmt.Errorf("hg: line %d: trailing junk in authorized key", i)
		}

		keys = append(keys, AuthorizedKey{
			PublicKey: out,
			Options:   options,
			Comment:   comment,
		})
	}

	*a = keys
	return nil
}
