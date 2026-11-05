package bench

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"math/rand/v2"
	"strings"
	"time"
)

// Key material is derived from the seeded stream instead of crypto/rand, so the corpus is
// byte-identical per seed. These are throwaway keys that protect nothing.

// detReader adapts the seeded stream to io.Reader for APIs that want entropy.
type detReader struct{ r *rand.Rand }

func (d detReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.r.Uint64())
	}
	return len(p), nil
}

func detPrime(r *rand.Rand, bits int) *big.Int {
	b := make([]byte, bits/8)
	for {
		detReader{r}.Read(b)
		b[0] |= 0xc0 // top two bits set, so p*q always has the full modulus length
		b[len(b)-1] |= 1
		c := new(big.Int).SetBytes(b)
		if c.ProbablyPrime(20) {
			return c
		}
	}
}

func detRSA(r *rand.Rand, bits int) *rsa.PrivateKey {
	one := big.NewInt(1)
	e := big.NewInt(65537)
	for {
		p, q := detPrime(r, bits/2), detPrime(r, bits/2)
		if p.Cmp(q) == 0 {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}
		k := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		k.Precompute()
		if k.Validate() != nil {
			continue
		}
		return k
	}
}

func pemString(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

// rsaPEM is the traditional "RSA PRIVATE KEY" form ssh-keygen -m PEM and openssl genrsa write.
func rsaPEM(r *rand.Rand, bits int) string {
	return pemString("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(detRSA(r, bits)))
}

// pkcs8PEM is the "PRIVATE KEY" form Google service-account files carry.
func pkcs8PEM(r *rand.Rand, bits int) string {
	der, err := x509.MarshalPKCS8PrivateKey(detRSA(r, bits))
	if err != nil {
		panic(err)
	}
	return pemString("PRIVATE KEY", der)
}

func ecPEM(r *rand.Rand) string {
	d := make([]byte, 32)
	for {
		detReader{r}.Read(d)
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
		if err != nil { // scalar out of range for the curve order; draw again
			continue
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			panic(err)
		}
		return pemString("EC PRIVATE KEY", der)
	}
}

func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// sshPEMType is spelled apart from the dashes on purpose: written whole, a source file holding the
// BEGIN and END lines is itself a private-key finding for every scanner, this one included.
const sshPEMType = "OPENSSH PRIVATE KEY"

// openSSHPEM writes the openssh-key-v1 container (unencrypted ed25519), the format
// ssh-keygen has produced by default since OpenSSH 9.5, with its 70-column wrapping.
func openSSHPEM(r *rand.Rand, comment string) string {
	seed := make([]byte, ed25519.SeedSize)
	detReader{r}.Read(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	kt := sshString([]byte("ssh-ed25519"))

	var section bytes.Buffer
	check := uint32(r.Uint64())
	section.Write(binary.BigEndian.AppendUint32(nil, check))
	section.Write(binary.BigEndian.AppendUint32(nil, check))
	section.Write(kt)
	section.Write(sshString(pub))
	section.Write(sshString(priv))
	section.Write(sshString([]byte(comment)))
	for pad := byte(1); section.Len()%8 != 0; pad++ {
		section.WriteByte(pad)
	}

	var out bytes.Buffer
	out.WriteString("openssh-key-v1\x00")
	out.Write(sshString([]byte("none")))
	out.Write(sshString([]byte("none")))
	out.Write(sshString(nil))
	out.Write(binary.BigEndian.AppendUint32(nil, 1))
	out.Write(sshString(append(append([]byte(nil), kt...), sshString(pub)...)))
	out.Write(sshString(section.Bytes()))

	b64 := base64.StdEncoding.EncodeToString(out.Bytes())
	var sb strings.Builder
	sb.WriteString("-----BEGIN " + sshPEMType + "-----\n")
	for len(b64) > 70 {
		sb.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	sb.WriteString(b64 + "\n-----END " + sshPEMType + "-----\n")
	return sb.String()
}

// publicPEM is a public key: material that looks like a key file and must never alert.
func publicPEM(r *rand.Rand) string {
	seed := make([]byte, ed25519.SeedSize)
	detReader{r}.Read(seed)
	der, err := x509.MarshalPKIXPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		panic(err)
	}
	return pemString("PUBLIC KEY", der)
}

// sshPublicLine is an authorized_keys entry for a fresh ed25519 key.
func sshPublicLine(r *rand.Rand, comment string) string {
	seed := make([]byte, ed25519.SeedSize)
	detReader{r}.Read(seed)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	blob := append(sshString([]byte("ssh-ed25519")), sshString(pub)...)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + comment
}

func certPEM(r *rand.Rand, cn string) string {
	seed := make([]byte, ed25519.SeedSize)
	detReader{r}.Read(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(r.Uint32()) + 1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Bench Labs"}},
		NotBefore:             t0,
		NotAfter:              t0.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(detReader{r}, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	return pemString("CERTIFICATE", der)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwt signs header.payload with HS256, the way Supabase and jwt.io samples do.
func jwt(header, payload any, key []byte) string {
	h, err := json.Marshal(header)
	if err != nil {
		panic(err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	signing := b64url(h) + "." + b64url(p)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(signing))
	return signing + "." + b64url(m.Sum(nil))
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// supabaseKey is a project key as the dashboard shows it: iss/ref/role/iat/exp.
type supabaseClaims struct {
	Iss  string `json:"iss"`
	Ref  string `json:"ref"`
	Role string `json:"role"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

func supabaseJWT(g *Gen, role string) string {
	iat := int64(1700000000 + g.intn(40_000_000))
	key := make([]byte, 32)
	detReader{g.r}.Read(key)
	return jwt(jwtHeader{"HS256", "JWT"}, supabaseClaims{
		Iss: "supabase", Ref: g.str(lower, 20), Role: role, Iat: iat, Exp: iat + 315360000,
	}, key)
}

type saFile struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
	UniverseDomain          string `json:"universe_domain"`
}

// serviceAccountJSON is the key file `gcloud iam service-accounts keys create` writes;
// firebase=true gives the firebase-adminsdk-<5>@ account the console's "generate new
// private key" button produces.
func serviceAccountJSON(g *Gen, firebase bool) (jsonText, pemText, email string) {
	project := g.pick([]string{"atlas", "harbor", "lumen", "orbit", "quartz", "relay", "summit", "tundra"}) +
		"-" + g.str(lowerNum, 6)
	name := "ci-deployer"
	if firebase {
		name = "firebase-adminsdk-" + g.str(lowerNum, 5)
	}
	email = name + "@" + project + ".iam.gserviceaccount.com"
	pemText = pkcs8PEM(g.r, 2048)
	f := saFile{
		Type:                    "service_account",
		ProjectID:               project,
		PrivateKeyID:            g.str(hexLower, 40),
		PrivateKey:              pemText,
		ClientEmail:             email,
		ClientID:                g.str(digits, 21),
		AuthURI:                 "https://accounts.google.com/o/oauth2/auth",
		TokenURI:                "https://oauth2.googleapis.com/token",
		AuthProviderX509CertURL: "https://www.googleapis.com/oauth2/v1/certs",
		ClientX509CertURL:       "https://www.googleapis.com/robot/v1/metadata/x509/" + strings.ReplaceAll(email, "@", "%40"),
		UniverseDomain:          "googleapis.com",
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		panic(err)
	}
	return strings.TrimRight(buf.String(), "\n"), strings.TrimRight(pemText, "\n"), email
}

// jsonString renders s as a JSON string literal without HTML escaping.
func jsonString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		panic(err)
	}
	return strings.TrimRight(buf.String(), "\n")
}

// jsonEscaped is the inside of jsonString: what the value looks like between the quotes.
func jsonEscaped(s string) string {
	j := jsonString(s)
	return j[1 : len(j)-1]
}

// jwtIO builds the canonical jwt.io sample token from its parts. It is public
// documentation, not a secret, but a scanner can not tell, so it is a negative.
func jwtIO() string {
	type claims struct {
		Sub  string `json:"sub"`
		Name string `json:"name"`
		Iat  int64  `json:"iat"`
	}
	return jwt(jwtHeader{"HS256", "JWT"}, claims{"1234567890", "John Doe", 1516239022}, []byte("your-256-bit-secret"))
}
