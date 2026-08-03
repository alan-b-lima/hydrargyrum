package hg

import "testing"

func Test_ParseAddr(t *testing.T) {
	type Test struct {
		Addr string

		User, Host string
		WantErr    bool
	}

	tests := []Test{
		{Addr: "ssh://gopher@192.168.1.62:22", User: "gopher", Host: "192.168.1.62:22"},
		{Addr: "gopher@192.168.1.62:8022", User: "gopher", Host: "192.168.1.62:8022"},
		{Addr: "gopher@192.168.1.62:ssh", User: "gopher", Host: "192.168.1.62:ssh"},
		{Addr: "gopher@go.dev", User: "gopher", Host: "go.dev:ssh"},
		{Addr: "gopher@[ffff::1]:75", User: "gopher", Host: "[ffff::1]:75"},
		{Addr: "gopher@[ffff::192.168.1.14]", User: "gopher", Host: "[ffff::192.168.1.14]:ssh"},
		{Addr: "ssh://the-blue-gopher@go.dev", User: "the-blue-gopher", Host: "go.dev:ssh"},
		{Addr: "gopher@ffff::192.168.1.14", WantErr: true},
		{Addr: "ssh://@go.dev", WantErr: true},
		{Addr: "@go.dev", WantErr: true},
		{Addr: "gopher@go.dev:http", WantErr: true},
		{Addr: "Gopher@go.dev", WantErr: true},
		{Addr: "ssh://the-blue.gopher@go.dev", WantErr: true},
		{Addr: "ssh://blueGopher@go.dev", WantErr: true},
	}

	for _, test := range tests {
		t.Run(test.Addr, func(t *testing.T) {
			user, host, err := ParseAddr(test.Addr)
			switch {
			case err == nil && !test.WantErr:
				if user != test.User {
					t.Errorf("want user %+q, got %+q", test.User, user)
				}

				if host != test.Host {
					t.Errorf("want host %+q, got %+q", test.Host, host)
				}

			case err == nil && test.WantErr:
				t.Error("got no error")

			case err != nil && !test.WantErr:
				t.Errorf("got error %v", err)

			case err != nil && test.WantErr:
				// good
			}
		})
	}
}
