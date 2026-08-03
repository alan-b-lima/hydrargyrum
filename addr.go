package hg

import (
	"fmt"
	"net"
	"strings"
)

// ParseAddr extracts the relevant parts from a [user@]hostname or a URI of the
// form.
//
// ParseAddr accepts the following format:
//
//	[ "ssh://" ] [ User "@" ] Hostname [ ":" Port ]
//
// The return user is the User part, which may be empty. The return host is
// Hostname:ssh if no port is specified, or Hostname:Port otherwise.
func ParseAddr(addr string) (user, host string, err error) {
	const scheme = "ssh://"

	var offset int
	defer func() {
		if err != nil {
			err = fmt.Errorf("byte offset %d: %w", offset, err)
		}
	}()

	if strings.HasPrefix(addr, scheme) {
		addr = addr[len(scheme):]
		offset = len(scheme)
	}

	if before, after, ok := strings.Cut(addr, "@"); ok {
		user, addr = before, after
		if user == "" {
			err = fmt.Errorf("empty user name with trailing @")
			return
		}

		for i, rune := range user {
			switch {
			case '0' <= rune && rune <= '9':
			case 'a' <= rune && rune <= 'z':
			case rune == '_':
			case rune == '-':

			default:
				offset += i
				if len(user) > 10 {
					err = fmt.Errorf("illegal rune %+q in %+q... user name", rune, user[:10])
				} else {
					err = fmt.Errorf("illegal rune %+q in %+q user name", rune, user)
				}
				return
			}
		}

		// count the @ as well
		offset += len(user) + 1
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port, err = net.SplitHostPort(addr + ":ssh")
		if err != nil {
			return
		}
	}

	host = net.JoinHostPort(host, port)

	if !strings.HasSuffix(host, ":ssh") {
		for i, rune := range port {
			if rune < '0' || '9' < rune {
				offset += i
				err = fmt.Errorf("illegal rune %+q in port", rune)
				return
			}
		}
	}

	return user, host, nil
}
