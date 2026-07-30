package identify

import "testing"

// TestDecodeJA4 covers the structured segment of a JA4 fingerprint, which is
// where the value is: it yields real facts about every TLS client on the
// network without needing a fingerprint database at all.
func TestDecodeJA4(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  JA4
		wantK bool
	}{
		{
			name: "full fingerprint, TLS 1.3 browser over TCP",
			in:   "t13d1516h2_8daaf6152771_e5627efa2ab1",
			want: JA4{Transport: "TCP", TLSVersion: "TLS 1.3", SNI: true,
				Ciphers: 15, Extensions: 16, ALPN: "HTTP/2", OK: true},
			wantK: true,
		},
		{
			name: "leading segment alone parses identically",
			in:   "t13d1516h2",
			want: JA4{Transport: "TCP", TLSVersion: "TLS 1.3", SNI: true,
				Ciphers: 15, Extensions: 16, ALPN: "HTTP/2", OK: true},
			wantK: true,
		},
		{
			name: "QUIC transport and HTTP/3",
			in:   "q13d0310h3_55b375c5d22e_cd85d2d88918",
			want: JA4{Transport: "QUIC", TLSVersion: "TLS 1.3", SNI: true,
				Ciphers: 3, Extensions: 10, ALPN: "HTTP/3", OK: true},
			wantK: true,
		},
		{
			name: "no SNI means the client dialled a bare IP",
			in:   "t12i0908h1_1234567890ab_1234567890ab",
			want: JA4{Transport: "TCP", TLSVersion: "TLS 1.2", SNI: false,
				Ciphers: 9, Extensions: 8, ALPN: "HTTP/1.1", OK: true},
			wantK: true,
		},
		{
			name: "obsolete client is flagged",
			in:   "t10d0704h1_1234567890ab_1234567890ab",
			want: JA4{Transport: "TCP", TLSVersion: "TLS 1.0", Obsolete: true,
				SNI: true, Ciphers: 7, Extensions: 4, ALPN: "HTTP/1.1", OK: true},
			wantK: true,
		},
		{
			name: "SSL 3.0 is obsolete",
			in:   "ts3d0503h1",
			want: JA4{Transport: "TCP", TLSVersion: "SSL 3.0", Obsolete: true,
				SNI: true, Ciphers: 5, Extensions: 3, ALPN: "HTTP/1.1", OK: true},
			wantK: true,
		},
		{
			name: "DNS-over-TLS is recognised",
			in:   "t13d1112dt",
			want: JA4{Transport: "TCP", TLSVersion: "TLS 1.3", SNI: true,
				Ciphers: 11, Extensions: 12, ALPN: "DNS-over-TLS", OK: true},
			wantK: true,
		},
		{
			name: "no ALPN offered",
			in:   "t12d060400",
			want: JA4{Transport: "TCP", TLSVersion: "TLS 1.2", SNI: true,
				Ciphers: 6, Extensions: 4, ALPN: "", OK: true},
			wantK: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodeJA4(tc.in)
			if got != tc.want {
				t.Errorf("DecodeJA4(%q)\n got %+v\nwant %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestDecodeJA4RejectsGarbage is the important half. A JA3 hash or a truncated
// string must not decode into a confident-looking TLS configuration — reporting
// invented facts about a device is worse than reporting nothing.
func TestDecodeJA4RejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"t13d15",                           // truncated
		"t13d1516h2x",                      // too long
		"771,4865-4866-4867,0-23-65281",    // a JA3 string
		"e7d705a3286e19ea42f587b344ee6865", // a JA3 hash
		"x13d1516h2",                       // unknown transport
		"t99d1516h2",                       // unknown version
		"t13x1516h2",                       // neither d nor i
		"t13dAB16h2",                       // non-numeric cipher count
	} {
		if got := DecodeJA4(in); got.OK {
			t.Errorf("DecodeJA4(%q) reported OK with %+v; garbage must not parse", in, got)
		}
	}
}

// TestJA4FlagsObsoleteClient checks the end-to-end path: a device whose own
// fingerprint says it offers TLS 1.0 is a finding the server-side version check
// cannot produce, because the offer happens before anything is negotiated.
func TestJA4FlagsObsoleteClient(t *testing.T) {
	r := NewResolver()
	d := r.device("10.0.5.5")
	r.applyJA4(d, "t10d0704h1_1234567890ab_1234567890ab")

	if !d.JA4["t10d0704h1_1234567890ab_1234567890ab"] {
		t.Error("fingerprint was not recorded on the device")
	}

	var found bool
	for _, f := range r.Findings() {
		if f.Kind == "client-obsolete-tls" && f.Device == "10.0.5.5" {
			found = true
		}
	}
	if !found {
		t.Error("no client-obsolete-tls finding for a device offering TLS 1.0")
	}
}

// TestJA4ModernClientProducesNoFinding guards the other direction: the common
// case must stay silent, or the finding list fills with noise and stops being
// read at all.
func TestJA4ModernClientProducesNoFinding(t *testing.T) {
	r := NewResolver()
	r.applyJA4(r.device("10.0.5.6"), "t13d1516h2_8daaf6152771_e5627efa2ab1")

	for _, f := range r.Findings() {
		if f.Kind == "client-obsolete-tls" {
			t.Errorf("TLS 1.3 client produced %q", f.Kind)
		}
	}
}
