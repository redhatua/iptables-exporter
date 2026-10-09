package main

import "testing"

func TestValidateMetricsPath(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
	}{
		{"/metrics", true},
		{"/custom/metrics", true},
		{"", false},
		{"metrics", false},
		{"/", false},
		{"/healthz", false},
		{"/-/ready", false},
		{"/metrics/{", false},
		{"/a{b}", false},
		{"/a}b", false},
		{"/a b", false},
	}
	for _, tc := range cases {
		err := validateMetricsPath(tc.path)
		if (err == nil) != tc.ok {
			t.Errorf("validateMetricsPath(%q) = %v, want ok=%v", tc.path, err, tc.ok)
		}
	}
}
