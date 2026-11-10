package install

import (
	"reflect"
	"testing"
)

func TestParseSSHPorts(t *testing.T) {
	cases := []struct {
		name, config string
		want         []int
	}{
		{"default", "PermitRootLogin no\n", []int{22}},
		{"port line", "Port 2222\n", []int{2222}},
		{"port with equals", "Port=2222\n", []int{2222}},
		{"port with spaced equals", "Port = 2222\n", []int{2222}},
		{"listen address with equals", "ListenAddress = 0.0.0.0:2200\n", []int{2200}},
		{"listen address with port", "ListenAddress 0.0.0.0:2200\n", []int{2200}},
		{"listen address ipv6 with port", "ListenAddress [::]:2201\n", []int{2201}},
		{"bare ipv6 listen address keeps default", "ListenAddress ::\n", []int{22}},
		{"duplicates collapse", "Port 2222\nListenAddress 0.0.0.0:2222\n", []int{2222}},
		{"trailing comment", "Port 2222 # moved\n", []int{2222}},
		{"commented port ignored", "#Port 2200\nPort 2222\n", []int{2222}},
		{"listen address with rdomain", "ListenAddress 0.0.0.0:2200 rdomain mgmt\n", []int{2200}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseSSHPorts(c.config); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("parseSSHPorts = %v, want %v", got, c.want)
			}
		})
	}
}
