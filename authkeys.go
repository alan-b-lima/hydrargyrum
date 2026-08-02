package hg

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
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
	for i, key := range a {
		if i > 0 {
			b = append(b, ' ')
		}

		b, _ = key.AppendText(b) // it cannot fail
	}

	return b, nil
}

func (a AuthorizedKeys) MarshalText() ([]byte, error) {
	return a.AppendText(nil)
}

// UnmarshalText unmarshal a authorized_keys file used by OpenSSH, accourding
// to the [sshd(8)] manual.
//
// [sshd(8)]: https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
func (a *AuthorizedKeys) UnmarshalText(b []byte) error {
	var keys []AuthorizedKey
	for i := 1; len(b) > 0; i++ {
		var line []byte
		if j := bytes.IndexByte(line, '\n'); j >= 0 {
			line, b = b[:j], b[j+1:]
		} else {
			line, b = b, nil
		}

		line = trimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		var key AuthorizedKey
		if err := key.UnmarshalText(line); err != nil {
			return fmt.Errorf("hg: line %d: %w", i, err)
		}

		keys = append(keys, key)
	}

	*a = keys
	return nil
}

func (a AuthorizedKey) AppendText(b []byte) ([]byte, error) {
	buf := bytes.NewBuffer(b)

	for i, opt := range a.Options {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(opt)
	}
	if len(a.Options) > 0 {
		buf.WriteByte(' ')
	}

	buf.WriteString(a.Type())
	buf.WriteByte(' ')

	b = base64.StdEncoding.AppendEncode(buf.Bytes(), a.Marshal())
	buf = bytes.NewBuffer(b)

	if len(a.Comment) > 0 {
		buf.WriteByte(' ')
		buf.WriteString(a.Comment)
	}

	return buf.Bytes(), nil
}

func (a AuthorizedKey) MarshalText() ([]byte, error) {
	return a.AppendText(nil)
}

// UnmarshalText splits the authorized key line into its fields and decodes
// them properly.
//
// The OpenSSH format, described in [ssh(8)] is as follows:
//
//	[ Options ] KeyType Base64Key [ Comment ]
//
// Fields are space-separated and no spaces may exists, except within double
// quotes in the Options field.
//
// If the line has three fields, format is ambiguous:
//
//	KeyType Base64Key Comment
//	Options KeyType Base64Key
//
// Both productions are valid and indistinguishable based on field separation
// alone.
//
// [sshd(8)]: https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
func (a *AuthorizedKey) UnmarshalText(line []byte) error {
	var fields [4][]byte

	var i int
	for i = 0; len(line) > 0; i++ {
		if i > 4 {
			if len(trimSpace(line)) == 0 {
				break
			}

			return errors.New("too many fields")
		}

		fields[i], line = nextField(line)
	}

	optsBytes, typeBytes, base64KeyBytes, commentBytes, err := lineFields(fields[:i])
	if err != nil {
		return err
	}

	var ak AuthorizedKey

	for opt := range bytes.SplitSeq(optsBytes, []byte{','}) {
		ak.Options = append(ak.Options, string(opt))
	}

	key := make([]byte, 0, base64.StdEncoding.DecodedLen(len(base64KeyBytes)))
	key, err = base64.StdEncoding.AppendDecode(key, base64KeyBytes)
	if err != nil {
		return err
	}

	out, err := ssh.ParsePublicKey(base64KeyBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	if !bytes.Equal([]byte(out.Type()), typeBytes) {
		return fmt.Errorf("type mismatch: human-readable type %q, encoded type %q", typeBytes, out.Type())
	}

	ak.Comment = string(commentBytes)

	*a = ak
	return nil
}

func lineFields(fields [][]byte) (opts, typ, key, comment []byte, err error) {
	switch len(fields) {
	case 0, 1:
		err = errors.New("incomplete authorized key line")
		return

	case 4:
		opts = fields[0]
		typ = fields[1]
		key = fields[2]
		comment = fields[3]
		return // Options KeyType Base64Key Comment

	case 3:
		break // Options KeyType Base64Key | KeyType Base64Key Comment

	case 2:
		typ = fields[0]
		key = fields[1]
		return // KeyType Base64Key
	}

	if possibleKey(fields[1], fields[2]) || bytes.ContainsAny(fields[0], "\t \",") {
		opts = fields[0]
		typ = fields[1]
		key = fields[2]
		return // Options KeyType Base64Key
	}

	if possibleKey(fields[0], fields[1]) {
		typ = fields[0]
		key = fields[1]
		comment = fields[2]
		return // KeyType Base64Key Comment
	}

	err = errors.New("malformed line")
	return
}

func possibleKey(typ, key []byte) bool {
	// Per RFC 4251 section 6, algorithm names are no longer than 64 bytes.
	// This is technically wrong, since it may identify a bad Type as Options,
	// but then Key will likely fails later.
	//
	// Per RFC 4253 section 6.6, the public key is encoded, in the SSH wire
	// format, with a string followed by arbitrary binary data. The string is
	// the algorithm name, also under RFC 4251 section 6, so it must be no
	// longer than 64 bytes. The length of that string is the big-endian 32bit
	// number from the first four bytes.

	if len(typ) > 64 {
		return false
	}

	if len(key) < 8 {
		return false
	}

	var block [6]byte
	n, err := base64.StdEncoding.Decode(block[:], key[:8])
	if n != 6 || err != nil {
		return false
	}

	length := binary.BigEndian.Uint32(block[:4])
	if length > 64 {
		return false
	}

	return true
}

func nextField(s []byte) ([]byte, []byte) {
	for lo, b := range s {
		switch b {
		case '\t', ' ':
			continue
		}
		s = s[lo:]
		break
	}

	var quote bool
	for hi, b := range s {
		switch b {
		case '\t', ' ':
			if quote {
				return s[:hi], s[hi:]
			}

		case '"':
			quote = !quote
		}
	}

	return s, nil
}

func trimSpace(s []byte) []byte {
	for lo, b := range s {
		switch b {
		case '\t', ' ':
			continue
		}
		s = s[lo:]
		break
	}

	for hi := len(s) - 1; hi >= 0; hi-- {
		b := s[hi]
		switch b {
		case '\t', ' ':
			return s[:hi+1]
		}
	}

	return nil
}
