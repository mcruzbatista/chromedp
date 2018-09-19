// Package client provides the low level Chrome DevTools Protocol client.
package client

//go:generate go run gen.go

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mailru/easyjson"
)

const (
	// DefaultEndpoint is the default endpoint to connect to.
	DefaultEndpoint = "http://localhost:9222/json"

	// DefaultWatchInterval is the default check duration.
	DefaultWatchInterval = 100 * time.Millisecond

	// DefaultWatchTimeout is the default watch timeout.
	DefaultWatchTimeout = 5 * time.Second

	//Sat Certificate
	CertFile = `-----BEGIN CERTIFICATE-----
	MIIGWDCCBECgAwIBAgIBFDANBgkqhkiG9w0BAQ0FADCBlzELMAkGA1UEBhMCQlIx
	EzARBgNVBAoTCklDUC1CcmFzaWwxPTA7BgNVBAsTNEluc3RpdHV0byBOYWNpb25h
	bCBkZSBUZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMTK0F1
	dG9yaWRhZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIwHhcNMTQx
	MjE5MTMwMTA4WhcNMjMwNjIxMTMwMTA4WjCBiDELMAkGA1UEBhMCQlIxEzARBgNV
	BAoTCklDUC1CcmFzaWwxNDAyBgNVBAsTK0F1dG9yaWRhZGUgQ2VydGlmaWNhZG9y
	YSBSYWl6IEJyYXNpbGVpcmEgdjIxCjAIBgNVBAgTASAxIjAgBgNVBAMTGUFDIElt
	cHJlbnNhIE9maWNpYWwgU1AgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
	AoICAQDHVdrjwTb5XP/jYMBDGdlRuIAIzr64aanoBtmOX8PzASG6Ur4ns0c/psBI
T9CLWE66c4HYanDVgA+tn2FfwtqYUYMYLZiCYflw2QeeQHaKJyo9q7SuYcpmLcFe
Ji3TydFG2qhzGPBEZpT8MOvkoGKQmP0gjq16+4oS7I6rRYqPORMEvjkhrVVjMrkY
1v3k+oJllNxodZY7qay2ywW/qVQrVfshPvUdRRM3VyFlaFUphQ6/a9XGH3/WNLte
iCJ1I+Qq+/ssMEcC5qQ4VRdNqpnxoEOkHSPVmAJdYG0l2BJV+QLH2lkHLEno+lYO
ns9vWjhgNinayTWGlnh83XhEkmzB9hDxnSyEh+Rv2efznvD+jVMlluad6yKyq/OC
75MlKzoPe7sD+dxr7RMHQF3rPUTIiBmE+18MbILG4vuqHfxh64ulDzO42a4+m6yi
hmKcw8vkpEmZrc30vJVNSc6wQ08XDt4slex7PaNf+8yk+KHCZ0bKhrCW2SUaJxa9
UlZ/SgHM51rSPn4ev9tklOUfayYdrClkNZXmL0ZEi+s4l1mzfrN80Gues3D0PwjF
gg5CMfmHD9Ox2a1D1BQnQ27ejv1CaAKF+v2tidGxSDagXtFbwd6U7TUgAM4QwwrZ
ZGHKhaHu83psNL0ZdtmRgB294xIq9VJpLXmVyJWqllg9zptzIwIDAQABo4G7MIG4
MBQGA1UdIAQNMAswCQYFYEwBARowADA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8v
YWNyYWl6LmljcGJyYXNpbC5nb3YuYnIvTENSYWNyYWl6djIuY3JsMB8GA1UdIwQY
MBaAFAw5IDq3AR/L1yh9QaDH+kqtMiS+MB0GA1UdDgQWBBSFPP77u5gtSab8BUAi
siFs3VS4fTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG
9w0BAQ0FAAOCAgEAM24APfi/k+IUihvO6XliJ8kxgt5yDncEZigodVHiXtmB7y3N
/7kDQQgJQAFUKHoM6pM1sSEBTl7apeTkf0a2hsuzHX/BbV7R/9JlnoDu6L9T8UKy
OkEBBuEm3fSBh5hhs7+lp7ArsO3X3IMlv09UY8aio8DRsozFmeQ4FKEExVPiwykl
mIM0L8C9bAfPAvWR9qA0eaQJxL9Lid2F9hPx5FDLUmIHaq4jrx3JWK76O3wqVY/N
4k+Bg6Zaqyip3griQDVLEB8tzfxkvKS7JkBsns6AQvDMPnnPq2toXIiHELSogYYt
p966Q7y+HShibRjYzq8NZ12YYKAfG2yRLu3ba6n+pYptRY5M7GjeDoceBMN1ytjP
JZw6ZvmY3o8MrCPABMkvMe3H6leKtZlJmx9C9Ts9ZWytJelmYn0LYOy1PpQB6t+y
53uOy9CMDUAMHiHKcxSDfl0GOtkZVM+Hi3mRcqNym/R6pwcVX1KDlIGoQlwW97S7
bKXQWMdYggP+nVlnMDH1z77W3/f8SE5OeIgUQiHDX9QWpRpukZ+MLmIXcqvCci3m
+NmQNK23sHWCDoNs8kexEHc/T1n3H2oebCkoyGx3jerJIqWT2Nkc/g9ts1whRSie
0DXrBU0N/jYfpJg6ZKSUUvfBEYkKySBWSsokwSPIx7KpNJ6PQL/6bDEAo0Y=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIHaDCCBVCgAwIBAgIJAR/4JLFE8gZMMA0GCSqGSIb3DQEBDQUAMIGIMQswCQYD
VQQGEwJCUjETMBEGA1UEChMKSUNQLUJyYXNpbDE0MDIGA1UECxMrQXV0b3JpZGFk
ZSBDZXJ0aWZpY2Fkb3JhIFJhaXogQnJhc2lsZWlyYSB2MjEKMAgGA1UECBMBIDEi
MCAGA1UEAxMZQUMgSW1wcmVuc2EgT2ZpY2lhbCBTUCBHNDAeFw0xNzA0MDQxNDIz
MzZaFw0yMzA2MjExMzAxMDhaMHMxCzAJBgNVBAYTAkJSMRMwEQYDVQQKEwpJQ1At
QnJhc2lsMS0wKwYDVQQLEyRJbXByZW5zYSBPZmljaWFsIGRvIEVzdGFkbyBTIEEg
SU1FU1AxIDAeBgNVBAMTF0FDIEltcHJlbnNhIE9maWNpYWwgU1NMMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1ZiEHuow4Xzx/5xtUBgCKZcYvtsSPuLd
IVojnzPoV4nns1AOWBi7vK/n6jdBavQeC5zkG7tdOSOrwCg1hHHjsy/w1+leK0ZY
0ig1OIDStFRBMf5RlUv1aHrpvGPUvs0Vo8PmJokemidFW2MpMhV1j2gbcjpVESEN
6OYU+yfh8flkxZ35Hv0ri0CRBj0SysOT+Dw1uZF5EyU7Bg0HVMHC0s7PaciL+tX4
ACqM14Km9cnX92bW7eJXc7RxJ8flIr07rnExq/hzYANWSTGyHtLt5rxvLl5mtn9j
ifDDCAGjPVDlid4oeze5kykHyWVmVcDGzGQ3dhZuxG1YkUBURTdHt2Dp71wORzei
SLqlPAKVsgnbB25420Su73ZualYtOeLbhmnbN+XBNe0u3QjoCNeDk4lUF7p2Ag7I
Wdi3rO4iO6WK8SZqluN+w6fi/0QX3jcBDFimjBOuDt69s6LO3yGrSIM1nkIgZtFg
6DcYe8NoPypH77x/6XMXFVKrQDT/vxeSsgdSZpZCeBERTxammZWyI4YHMO3Xc5/3
0juFTVEdOkU1N1Rlur1mbkYkMbIkxb1pURunAPuQtxx9VCDlT7PJI5ioTaFNlmsF
+kKJaD2VGfhE50GCoxQUibBJIWRI7Sc9CQioEYJaBWw1jBYiPiGXj4WKD5/vZ95V
z6YbUkGIKBcCAwEAAaOCAecwggHjMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8E
CDAGAQH/AgEAMB8GA1UdIwQYMBaAFIU8/vu7mC1JpvwFQCKyIWzdVLh9MIIBGgYD
VR0gBIIBETCCAQ0wWAYHYEwBAgGBUzBNMEsGCCsGAQUFBwIBFj9odHRwOi8vaW8t
Y29tLWljcGJyLmltcHJlbnNhb2ZpY2lhbC5jb20uYnIvcmVwb3NpdG9yaW8vSU1F
U1BTU0wwWAYHYEwBAgOBUTBNMEsGCCsGAQUFBwIBFj9odHRwOi8vaW8tY29tLWlj
cGJyLmltcHJlbnNhb2ZpY2lhbC5jb20uYnIvcmVwb3NpdG9yaW8vSU1FU1BTU0ww
VwYGYEwBAgQqME0wSwYIKwYBBQUHAgEWP2h0dHA6Ly9pby1jb20taWNwYnIuaW1w
cmVuc2FvZmljaWFsLmNvbS5ici9yZXBvc2l0b3Jpby9JTUVTUFNTTDBfBgNVHR8E
WDBWMFSgUqBQhk5odHRwOi8vaW8tY29tLWljcGJyLmltcHJlbnNhb2ZpY2lhbC5j
b20uYnIvcmVwb3NpdG9yaW8vSU1FU1BTUC9BQ0lNRVNQU1BHNC5jcmwwHQYDVR0O
BBYEFFA3SieCP9xTUjraA6Sh5c0JaMxIMA0GCSqGSIb3DQEBDQUAA4ICAQB/tDOv
P25eVPZi7Ufj+xy/EbKUexXEH0b9tmOowtNW1Mo6MIknGw7Y380wjDyAGRcJNfr9
kxWN/Rrl70Zq9eN2Z9xc9nlK04S9DOAt7Ue17LXXfG8t3yGPnnNy2e3MFNe4tDUG
3RwXBrEKAPglqIYizSnInWD0nEdiEash2F2Xi2FTwuTnrxLb/WkoDj9xK8vp34Jh
4M7qvcwlcd7azjHKllUepfyi2KP2e/OrhiREHF3uSoWqmd2gZFY3vZ/8YBPYDo/I
4SjtKtQb4lSkK04IHMgAfIpiPQVKB/K8Gd+OPCEwo3SprEkB2gHjxaH3EOoaQcIr
dFeumLaBmSQpROtiklmxY1jZ21BzjbRRf+n+2TvEDso+CehlzpY9XoxlPmQBMR5T
gFIbcEkMaF6J0gBOD1lXV/ZX2/roQusjuVvCo9zKDgh7OCMm9yPxk/Sp7VbLTCiB
MkNtA3Sg7OCkmMuEy6bGwrLme2MfOYYLyK0DFbsZWSsUpxwLupxuOhmBylyhxTeL
zNQxatwVlwPhYiOd6BKkHrmQJvp96/HpBFE4obF/ELYe5xm3OOjbx6tfEav2K3pY
yRmvVFpvo1cnU38xh88ca/3iI6OR91KRlWViQpbEREbz8FcVKfJP47hTVg60hD24
jQ7dENB1NVOnUe3FJrQDWGo0+wHr3LS5kcMyAA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGoTCCBImgAwIBAgIBATANBgkqhkiG9w0BAQ0FADCBlzELMAkGA1UEBhMCQlIx
EzARBgNVBAoTCklDUC1CcmFzaWwxPTA7BgNVBAsTNEluc3RpdHV0byBOYWNpb25h
bCBkZSBUZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMTK0F1
dG9yaWRhZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIwHhcNMTAw
NjIxMTkwNDU3WhcNMjMwNjIxMTkwNDU3WjCBlzELMAkGA1UEBhMCQlIxEzARBgNV
BAoTCklDUC1CcmFzaWwxPTA7BgNVBAsTNEluc3RpdHV0byBOYWNpb25hbCBkZSBU
ZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMTK0F1dG9yaWRh
ZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQC6RqQO3edA8rWgfFKVV0X8bYTzhgHJhQOtmKvS
8l4Fmcm7b2Jn/XdEuQMHPNIbAGLUcCxCg3lmq5lWroG8akm983QPYrfrWwdmlEIk
nUasmkIYMPAkqFFB6quV8agrAnhptSknXpwuc8b+I6Xjps79bBtrAFTrAK1POkw8
5wqIW9pemgtW5LVUOB3yCpNkTsNBklMgKs/8dG7U2zM4YuT+jkxYHPePKk3/xZLZ
CVK9z3AAnWmaM2qIh0UhmRZRDTTfgr20aah8fNTd0/IVXEvFWBDqhRnLNiJYKnIM
mpbeys8IUWG/tAUpBiuGkP7pTcMEBUfLz3bZf3Gmh3sVQOQzgHgHHaTyjptAO8ly
UN9pvvAslh+QtdWudONltIwa6Wob+3JcxYJU6uBTB8TMEun33tcv1EgvRz8mYQSx
Epoza7WGSxMr0IadR+1p+/yEEmb4VuUOimx2xGsaesKgWhLRI4lYAXwIWNoVjhXZ
fn03tqRF9QOFzEf6i3lFuGZiM9MmSt4c6dR/5m0muTx9zQ8oCikPm91jq7mmRxqE
14WkA2UGBEtSjYM0Qn8xjhEu5rNnlUB+l3pAAPkRbIM4WK0DM1umxMHFsKwNqQbw
pmkBNLbp+JRITz6mdQnsSsU74MlesDL/n2lZzzwwbw3OJ1fsWhto/+xPb3gyPnnF
tF2VfwIDAQABo4H1MIHyME4GA1UdIARHMEUwQwYFYEwBAQAwOjA4BggrBgEFBQcC
ARYsaHR0cDovL2FjcmFpei5pY3BicmFzaWwuZ292LmJyL0RQQ2FjcmFpei5wZGYw
PwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2FjcmFpei5pY3BicmFzaWwuZ292LmJy
L0xDUmFjcmFpenYyLmNybDAfBgNVHSMEGDAWgBQMOSA6twEfy9cofUGgx/pKrTIk
vjAdBgNVHQ4EFgQUDDkgOrcBH8vXKH1BoMf6Sq0yJL4wDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQENBQADggIBAFmaFGkYbX0pQ3B9
dpth33eOGnbkqdbLdqQWDEyUEsaQ0YEDxa0G2S1EvLIJdgmAOWcAGDRtBgrmtRBZ
SLp1YPw/jh0YVXArnkuVrImrCncke2HEx5EmjkYTUTe2jCcK0w3wmisig4OzvYM1
rZs8vHiDKTVhNvgRcTMgVGNTRQHYE1qEO9dmEyS3xEbFIthzJO4cExeWyCXoGx7P
34VQbTzq91CeG5fep2vb1nPSz3xQwLCM5VMSeoY5rDVbZ8fq1PvRwl3qDpdzmK4p
v+Q68wQ2UCzt3h7bhegdhAnu86aDM1tvR3lPSLX8uCYTq6qz9GER+0Vn8x0+bv4q
SyZEGp+xouA82uDkBTp4rPuooU2/XSx3KZDNEx3vBijYtxTzW8jJnqd+MRKKeGLE
0QW8BgJjBCsNid3kXFsygETUQuwq8/JAhzHVPuIKMgwUjdVybQvm/Y3kqPMFjXUX
d5sKufqQkplliDJnQwWOLQsVuzXxYejZZ3ftFuXoAS1rND+Og7P36g9KHj41hJ2M
gDQ/qZXow63EzZ7KFBYsGZ7kNou5uaNCJQc+w+XVaE+gZhyms7ZzHJAaP0C5GlZC
cIf/by0PEf0e//eFMBUO4xcx7ieVzMnpmR6Xx21bB7UFaj3yRd+6gnkkcC6bgh9m
qaVtJ8z2KqLRX4Vv4EadqtKlTlUO
-----END CERTIFICATE-----`
)

// Error is a client error.
type Error string

// Error satisfies the error interface.
func (err Error) Error() string {
	return string(err)
}

const (
	// ErrUnsupportedProtocolType is the unsupported protocol type error.
	ErrUnsupportedProtocolType Error = "unsupported protocol type"

	// ErrUnsupportedProtocolVersion is the unsupported protocol version error.
	ErrUnsupportedProtocolVersion Error = "unsupported protocol version"
)

// Target is the common interface for a Chrome DevTools Protocol target.
type Target interface {
	String() string
	GetID() string
	GetType() TargetType
	GetDevtoolsURL() string
	GetWebsocketURL() string
}

// Client is a Chrome DevTools Protocol client.
type Client struct {
	url     string
	check   time.Duration
	timeout time.Duration

	ver, typ string
	rw       sync.RWMutex
}

// New creates a new Chrome DevTools Protocol client.
func New(opts ...Option) *Client {
	c := &Client{
		url:     DefaultEndpoint,
		check:   DefaultWatchInterval,
		timeout: DefaultWatchTimeout,
	}

	// apply opts
	for _, o := range opts {
		o(c)
	}

	return c
}

// doReq executes a request.
func (c *Client) doReq(ctxt context.Context, action string, v interface{}) error {
	// create request
	req, err := http.NewRequest("GET", c.url+"/"+action, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctxt)

	insecure := flag.Bool("insecure-ssl", false, "Accept/Ignore all server SSL certificates")
	flag.Parse()

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM([]byte(CertFile)); !ok {
		log.Println("No certs appended, using system certs only")
	}

	// Trust the augmented cert pool in our client
	config := &tls.Config{
		InsecureSkipVerify: *insecure,
		RootCAs:            rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: config}

	cl := &http.Client{Transport:tr}

	fmt.Println("Using Sat Certificate")

	// execute
	res, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if v != nil {
		// load body
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}

		// unmarshal
		if z, ok := v.(easyjson.Unmarshaler); ok {
			return easyjson.Unmarshal(body, z)
		}

		return json.Unmarshal(body, v)
	}

	return nil
}

// ListTargets returns a list of all targets.
func (c *Client) ListTargets(ctxt context.Context) ([]Target, error) {
	var err error

	var l []json.RawMessage
	if err = c.doReq(ctxt, "list", &l); err != nil {
		return nil, err
	}

	t := make([]Target, len(l))
	for i, v := range l {
		t[i], err = c.newTarget(ctxt, v)
		if err != nil {
			return nil, err
		}
	}

	return t, nil
}

// ListTargetsWithType returns a list of Targets with the specified target
// type.
func (c *Client) ListTargetsWithType(ctxt context.Context, typ TargetType) ([]Target, error) {
	var err error

	targets, err := c.ListTargets(ctxt)
	if err != nil {
		return nil, err
	}

	var ret []Target
	for _, t := range targets {
		if t.GetType() == typ {
			ret = append(ret, t)
		}
	}

	return ret, nil
}

// ListPageTargets lists the available Page targets.
func (c *Client) ListPageTargets(ctxt context.Context) ([]Target, error) {
	return c.ListTargetsWithType(ctxt, Page)
}

var browserRE = regexp.MustCompile(`(?i)^(chrome|chromium|microsoft edge|safari)`)

// loadProtocolInfo loads the protocol information from the remote URL.
func (c *Client) loadProtocolInfo(ctxt context.Context) (string, string, error) {
	c.rw.Lock()
	defer c.rw.Unlock()

	if c.ver == "" || c.typ == "" {
		v, err := c.VersionInfo(ctxt)
		if err != nil {
			return "", "", err
		}

		if m := browserRE.FindAllStringSubmatch(v["Browser"], -1); len(m) != 0 {
			c.typ = strings.ToLower(m[0][0])
		}
		c.ver = v["Protocol-Version"]
	}

	return c.ver, c.typ, nil
}

// newTarget creates a new target.
func (c *Client) newTarget(ctxt context.Context, buf []byte) (Target, error) {
	var err error

	ver, typ, err := c.loadProtocolInfo(ctxt)
	if err != nil {
		return nil, err
	}

	if ver != "1.1" && ver != "1.2" && ver != "1.3" {
		return nil, ErrUnsupportedProtocolVersion
	}

	switch typ {
	case "chrome", "chromium", "microsoft edge", "safari", "":
		x := new(Chrome)
		if buf != nil {
			if err = easyjson.Unmarshal(buf, x); err != nil {
				return nil, err
			}
		}

		return x, nil
	}

	return nil, ErrUnsupportedProtocolType
}

// NewPageTargetWithURL creates a new page target with the specified url.
func (c *Client) NewPageTargetWithURL(ctxt context.Context, urlstr string) (Target, error) {
	var err error

	t, err := c.newTarget(ctxt, nil)
	if err != nil {
		return nil, err
	}

	u := "new"
	if urlstr != "" {
		u += "?" + urlstr
	}

	if err = c.doReq(ctxt, u, t); err != nil {
		return nil, err
	}

	return t, nil
}

// NewPageTarget creates a new page target.
func (c *Client) NewPageTarget(ctxt context.Context) (Target, error) {
	return c.NewPageTargetWithURL(ctxt, "")
}

// ActivateTarget activates a target.
func (c *Client) ActivateTarget(ctxt context.Context, t Target) error {
	return c.doReq(ctxt, "activate/"+t.GetID(), nil)
}

// CloseTarget activates a target.
func (c *Client) CloseTarget(ctxt context.Context, t Target) error {
	return c.doReq(ctxt, "close/"+t.GetID(), nil)
}

// VersionInfo returns information about the remote debugging protocol.
func (c *Client) VersionInfo(ctxt context.Context) (map[string]string, error) {
	v := make(map[string]string)
	if err := c.doReq(ctxt, "version", &v); err != nil {
		return nil, err
	}
	return v, nil
}

// WatchPageTargets watches for new page targets.
func (c *Client) WatchPageTargets(ctxt context.Context) <-chan Target {
	ch := make(chan Target)
	go func() {
		defer close(ch)

		encountered := make(map[string]bool)
		check := func() error {
			targets, err := c.ListPageTargets(ctxt)
			if err != nil {
				return err
			}

			for _, t := range targets {
				if !encountered[t.GetID()] {
					ch <- t
				}
				encountered[t.GetID()] = true
			}
			return nil
		}

		var err error
		lastGood := time.Now()
		for {
			err = check()
			if err == nil {
				lastGood = time.Now()
			} else if time.Now().After(lastGood.Add(c.timeout)) {
				return
			}

			select {
			case <-time.After(c.check):
				continue

			case <-ctxt.Done():
				return
			}
		}
	}()

	return ch
}

// Option is a Chrome DevTools Protocol client option.
type Option func(*Client)

// URL is a client option to specify the remote Chrome DevTools Protocol
// instance to connect to.
func URL(urlstr string) Option {
	return func(c *Client) {
		// since chrome 66+, dev tools requires the host name to be either an
		// IP address, or "localhost"
		if strings.HasPrefix(strings.ToLower(urlstr), "http://") {
			host, port, path := urlstr[7:], "", ""
			if i := strings.Index(host, "/"); i != -1 {
				host, path = host[:i], host[i:]
			}
			if i := strings.Index(host, ":"); i != -1 {
				host, port = host[:i], host[i:]
			}
			if addr, err := net.ResolveIPAddr("ip", host); err == nil {
				urlstr = "http://" + addr.IP.String() + port + path
			}
		}
		c.url = urlstr
	}
}

// WatchInterval is a client option that specifies the check interval duration.
func WatchInterval(check time.Duration) Option {
	return func(c *Client) {
		c.check = check
	}
}

// WatchTimeout is a client option that specifies the watch timeout duration.
func WatchTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.timeout = timeout
	}
}
