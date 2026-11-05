package pattern

import (
	"bytes"
	"crypto/sha256"
	"hash/crc32"
	"math"
	"regexp"
	"strings"
	"sync"

	"keyguard/internal/pattern/rules"
)

// The checks. They look at a value, and at the words before it on its line, and say what they
// can tell: a checksum that holds or fails, a shape that is an identifier or a template or a run of
// the alphabet, a text that reads like words. Each is a tag on the finding, and none drops it. Where a
// value is a secret is a question for the rule and for the reader of the report; a check that
// silences inside the engine would be one more thing in the engine that a lookalike can learn to get past.
//
// The tags are a closed vocabulary, shared with whatever reads findings (the engines adapter maps them
// to the tags core.Hit carries). A tag is a fact about a value, never a piece of it.
//
// The ideas of the shape checks (identifier, template, sequential run, uuid) are the ones every scanner
// reaches for, detect-secrets among them; the code here is written for this scanner and takes none
// of theirs. The word scorer and the digit test are this project's own.
const (
	TagChecksumOK  = "checksum-ok"     // a checksum the format carries holds
	TagChecksumBad = "checksum-bad"    // it does not: GitHub's CRC32 tail, a card number's Luhn digit
	TagTestValue   = "test-value"      // a value published as a test value (a payment test card)
	TagUUID        = "uuid"            // 8-4-4-4-12 hex
	TagHashLike    = "hash-like"       // all hex, the length of a digest, found by a generic rule
	TagTemplated   = "templated"       // ${VAR}, {{var}}, <placeholder>, %s, $VAR
	TagSequential  = "sequential"      // a stretch of the alphabet, of the digits, of a keyboard row, or one block repeated
	TagIDLike      = "id-like"         // the name before the value says it is an identifier or a digest
	TagWordy       = "wordy"           // it reads like words
	TagUnrandom    = "unlikely-random" // too many or too few digits for a random string of its alphabet
)

// tagsFor runs the checks on one finding. before is the text of the line up to the secret.
func tagsFor(r *rules.Rule, secret, before []byte) []string {
	var tags []string
	add := func(t string) { tags = append(tags, t) }
	if known, ok := githubChecksum(secret); known {
		if ok {
			add(TagChecksumOK)
		} else {
			add(TagChecksumBad)
		}
	}
	if isDigits(secret) && len(secret) >= 13 && len(secret) <= 19 {
		switch {
		case isTestPAN(secret):
			add(TagTestValue)
		case Luhn(secret):
			add(TagChecksumOK)
		default:
			add(TagChecksumBad)
		}
	}
	if isUUID(secret) {
		add(TagUUID)
	}
	generic := isGeneric(r)
	if generic && isDigestHex(secret) {
		add(TagHashLike)
	}
	if isTemplated(secret) {
		add(TagTemplated)
	}
	if isSequential(secret) {
		add(TagSequential)
	}
	if idLikeName(before) {
		add(TagIDLike)
	}
	if (generic || r.Filter.TokenRatio > 0) && Wordy(secret) {
		add(TagWordy)
	}
	if unlikelyRandom(secret) {
		add(TagUnrandom)
	}
	return tags
}

// ----- checksums -----

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// base62 writes v in GitHub's alphabet, left-padded with zeros to width.
func base62(v uint32, width int) []byte {
	var rev []byte
	for ; v > 0; v /= 62 {
		rev = append(rev, base62Alphabet[v%62])
	}
	for len(rev) < width {
		rev = append(rev, '0')
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// githubChecksum judges the tail of a classic GitHub token (ghp_, gho_, ghu_, ghs_, ghr_) or an npm
// token (npm_): 30 random characters and a 6 character checksum, the CRC32 of the 30 written in base 62.
// known is false for any other value, which has no checksum to check.
func githubChecksum(v []byte) (known, ok bool) {
	var body []byte
	switch {
	case len(v) == 40 && v[0] == 'g' && v[1] == 'h' && strings.IndexByte("pousr", v[2]) >= 0 && v[3] == '_':
		body = v[4:]
	case len(v) == 40 && bytes.HasPrefix(v, []byte("npm_")):
		body = v[4:]
	default:
		return false, false
	}
	for _, c := range body {
		if strings.IndexByte(base62Alphabet, c) < 0 {
			return false, false
		}
	}
	return true, bytes.Equal(body[30:], base62(crc32.ChecksumIEEE(body[:30]), 6))
}

// Luhn says whether a string of digits passes the Luhn test that payment card numbers carry.
func Luhn(digits []byte) bool {
	if len(digits) < 2 {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func isDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(b) > 0
}

// testPANs are the SHA-256 digests of the numbers payment providers publish for testing. They are
// digests so that no card-shaped literal sits in the source.
var testPANs = func() map[[sha256.Size]byte]struct{} {
	m := map[[sha256.Size]byte]struct{}{}
	for _, h := range []string{
		"9bbef19476623ca56c17da75fd57734dbf82530686043a6e491c6d71befe8f6e", "477bba133c182267fe5f086924abdc5db71f77bfc27f01f2843f2cdc69d89f05",
		"dd13cdf9af9dd3baf46ce96aecd7163cabf381ccb21e63f15f0fa10b1c663fa9", "68594afe9c9cda525f6aca7a7316ca06c9db4952ba6f5217944581dc4a07e0b6",
		"acd08f29a41f2e55ab0c4f774b1562b03ff01a905ed5b100f4facd43af572b1b", "2f725bbd1f405a1ed0336abaf85ddfeb6902a9984a76fd877c3b5cc3b5085a82",
		"304945e91de3deff52a61d08733141d72dd42ec9d47972f1060534d54c0c7f90", "b40e9bc7a74d50ab4f006ab0d3e85a8b96a5092989d5934623555f94ae48c836",
		"576c15a8072461c216efb9bd7306a6fc6039b43a6763c4c1a05930a2dd7b788f", "3a134ef77d4e2e4cdad2d2945ff1f76c1a23296c93c851f6244220a8cedea130",
		"53a8fc816e63b7a5ccd17aaff93f28bcf13abbf418209dcd93947722d7c326ba", "273476b83f26d858e3e62e1fc042e06961ed9229a428156d7ccfa096297267ff",
		"19ff47cc8024c133d5845d3f8938caca289929031e7d508c3adf7adff177f0c2", "d8086d483c15c711ebba19f966b97d3c2adcba74025ff8d7e07c3698c9531deb",
		"1c9d38ed26cd808fa3b02b9b3b988a7caf474e2e42d95789c0fe07e267c80d8f", "d79449f462cec9af0d857c3e1af888d4fa8bbdaa511b9eaaafcd2805c4ea6471",
		"51a4ae4c6ae999146474a67cbcb3b05fbcf4c17ab683043a066459da95513ea8", "f41e7ca4a3d71c4f047581f2ae2d6a8dbb8c58e51a020fa227edc724474aab6e",
		"7cbcc57fc39e4317fa8d55bb2d442f829f0c21ffa4c4683c48e7263faf1a871a", "44d1fb5dc4a2717ff21b10e26a70a531e4a30c5296d2817f534f6866e44f73bf",
		"49ed370182b3e634b99a7cb7dc4eb2c12ecb97a8f4f276a626a90b6ad4464a53", "c32066eec7feb6582d3c0390eb4d23b4830297ec75df82d6a7ef28251e99f077",
		"36a55e9a41bf19bdeae2a2e6ef2452aafc677c2927e5cd2a84d2b4525765a64c", "d516aad436666992226d2f194c458ba6509aca6cc4f003395771389d80f1f33c",
	} {
		var d [sha256.Size]byte
		for i := range d {
			d[i] = hexByte(h[2*i])<<4 | hexByte(h[2*i+1])
		}
		m[d] = struct{}{}
	}
	return m
}()

func hexByte(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

func isTestPAN(digits []byte) bool {
	_, ok := testPANs[sha256.Sum256(digits)]
	return ok
}

// ----- shapes -----

func isUUID(v []byte) bool {
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// isDigestHex: all hex, and as long as MD5, SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512 writes it.
func isDigestHex(v []byte) bool {
	switch len(v) {
	case 32, 40, 56, 64, 96, 128:
	default:
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

var templateRe = regexp.MustCompile(`^(?:\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]*\}\}|#\{[^}]*\}|%\{[^}]*\}|<[^<>\s]{1,60}>|\[[A-Za-z_ -]{1,40}\]|%[A-Za-z_]+%|@[A-Za-z_]+@|%[sdvq])$`)

// isTemplated: the whole value is a placeholder some template language fills in, or it holds the opener of one.
func isTemplated(v []byte) bool {
	return templateRe.Match(v) || bytes.Contains(v, []byte("${")) || bytes.Contains(v, []byte("{{")) || bytes.Contains(v, []byte("#{"))
}

var runs = []string{
	"abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba",
	"0123456789", "9876543210", "0123456789abcdef", "fedcba9876543210",
	"qwertyuiop", "asdfghjkl", "zxcvbnm", "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
}

// isSequential: the value is, ignoring case, a stretch of the alphabet, the digits or a keyboard row
// at least 8 long, or one short block written over and over.
func isSequential(v []byte) bool {
	if len(v) < 8 {
		return false
	}
	low := strings.ToLower(string(v))
	for _, run := range runs {
		if strings.Contains(run, low) {
			return true
		}
	}
	for n := 1; n <= len(low)/3 && n <= 8; n++ {
		if len(low)%n == 0 && strings.Repeat(low[:n], len(low)/n) == low {
			return true
		}
	}
	return false
}

var idNameRe = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_.\[\]-]*)["'` + "`" + `]?[ \t]*(?::=|=>|[:=])[ \t]*["'` + "`" + `(]*$`)

var idSuffixes = []string{"id", "uuid", "guid", "hash", "sha", "sha1", "sha256", "md5", "digest", "checksum", "etag",
	"revision", "rev", "commit", "version", "nonce", "fingerprint", "thumbprint", "integrity"}

// idLikeName: the name that an assignment before the value gives it ends in a word that says identifier or digest.
func idLikeName(before []byte) bool {
	if len(before) > 200 {
		before = before[len(before)-200:]
	}
	m := idNameRe.FindSubmatch(before)
	if m == nil {
		return false
	}
	name := strings.ToLower(string(m[1]))
	for _, s := range idSuffixes {
		if name == s || strings.HasSuffix(name, "_"+s) || strings.HasSuffix(name, "-"+s) || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	// camelCase: clientId, fileHash
	for _, s := range idSuffixes {
		cap := strings.ToUpper(s[:1]) + s[1:]
		if strings.HasSuffix(string(m[1]), cap) {
			return true
		}
	}
	return false
}

// ----- randomness -----

// unlikelyRandom is the digit test. A random string of letters and digits has about as many digits
// as the digits' share of its alphabet says, give or take a binomial spread; one with far fewer or far more
// (all letters, as an identifier is; mostly digits, as a number is) was not drawn that way. Only strings
// that use one clear alphabet and are long enough to judge are tested, and the bar is a tail probability
// of 1 in 1,000, so about that many true random keys are tagged and no key is dropped.
func unlikelyRandom(v []byte) bool {
	n := len(v)
	if n < 16 {
		return false
	}
	var digits, upper, lower int
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		default:
			return false // not plain alphanumerics: another test's business
		}
	}
	var p float64 // the digits' share of the alphabet
	switch {
	case upper > 0 && lower > 0:
		p = 10.0 / 62
	case upper > 0 || lower > 0:
		letters := upper + lower
		hexOnly := true
		for _, c := range v {
			if (c < '0' || c > '9') && (c|0x20 < 'a' || c|0x20 > 'f') {
				hexOnly = false
			}
		}
		if hexOnly {
			p = 10.0 / 16
		} else if letters > 0 {
			p = 10.0 / 36
		}
	default:
		return false // all digits
	}
	if p == 0 {
		return false
	}
	return binomialTail(n, p, digits) < 1e-3
}

// binomialTail is the probability, for n draws that each succeed with probability p, of a count at least
// as far from the mean as k on the side k is on.
func binomialTail(n int, p float64, k int) float64 {
	mean := float64(n) * p
	sum := 0.0
	if float64(k) <= mean {
		for i := 0; i <= k; i++ {
			sum += binomialPMF(n, p, i)
		}
	} else {
		for i := k; i <= n; i++ {
			sum += binomialPMF(n, p, i)
		}
	}
	return sum
}

func binomialPMF(n int, p float64, k int) float64 {
	lg := func(x int) float64 { v, _ := math.Lgamma(float64(x) + 1); return v }
	return math.Exp(lg(n) - lg(k) - lg(n-k) + float64(k)*math.Log(p) + float64(n-k)*math.Log(1-p))
}

// ----- words -----

// trainingWords is the text the word scorer learns what letters follow letters from: common English
// words and the vocabulary of configuration files and code. It is the scorer's own data, written for
// it; nothing is taken from another project's word list or tokenizer.
const trainingWords = `about above access account action active actual add address admin after again against agent all allow almost
alone along already also always amount and another answer any anything app apple application apply area argument around array
article ask asset assign attach attempt attribute audio author auto available average away back backend background balance bank
base basic batch because become been before begin behind being below best better between big binary bind bit black block blue body
book boot both bottom box branch break bridge bring broker browser buffer bug build bundle business busy button buy cache call
camera can cancel card care carry case catch category cause cell center certificate chain change channel character charge chart
chat check child choose circle class clean clear client clock close cloud cluster code collect color column come command comment
commit common company compare complete component config configuration connect connection console contact container content
context continue control copy core correct cost count country course cover create credential current custom customer cycle daily
dark data database date day deal debug decode default define delay delete deliver demo deny deploy depth describe design desktop
detail detect develop device dictionary different digital direct directory disable discover disk display distance divide document
domain done door double down download draft draw drive driver drop during each early earth easy edit effect either element email
empty enable encode end engine enough enter entry environment error escape event every exact example except exchange execute
exist exit expand expect expire explain export express extend external extra face fact fail fall false family fast feature feed
feel field fight file fill filter final find fine finish fire first fix flag flat float floor flow focus folder follow font food
force foreign forest forget form format forward found frame free fresh friend from front full function future game gate gather
general generate get give global goal good graph great green group grow guard guess guest guide hand handle happen hard hash have
head health hear heart heavy hello help here hidden high history hold home hook host hour house how human hundred idea identity
ignore image import include index info inner input insert inside install instance interface internal into invalid issue item job
join journal just keep kernel key kind know label language large last late launch layer lead learn least leave left length less
letter level library life light like limit line link list listen little live load local lock log long look loop lost low machine
mail main make manage many map mark master match material matter maybe mean media member memory menu merge message method middle
might mind minute mirror missing mobile mode model modern module money monitor month more most mount mouse move much music must
name native near need network never new next night node none normal note nothing notice number object offer office offline often
old once only open operation option order other output outside over owner package page pair panel parameter parent parse part
partner party pass password past patch path pattern pause payment peer people perform period permission person phone photo pick
picture piece pipe place plain plan plant platform play player please plugin point policy pool port position post power prefix
prepare present press pretty prevent previous price primary print priority private problem process product profile program
project promise property protect protocol provide proxy public pull purpose push query question queue quick quiet quote race
radio raise random range rate raw reach read ready real reason receive recent record recover redirect reduce reference refresh
region register reject related release reload remember remote remove render repeat replace reply report repository request
require reserve reset resolve resource respond response rest result retry return reverse review right ring rise role root
round route row rule run safe same sample save scale scan scene schedule schema school score screen script search second
section secure security seed select send sense sensor separate sequence serial server service session set setting setup several
shadow shape share sharp sheet shell shift ship short should show shut side sign signal similar simple since single site size
skip sleep slice slow small smart snap social socket soft solid some song soon sort sound source space speak special speed
spell split spot spring square stack stage stand standard start state static status stay step still stop storage store story
stream street strict string strong structure studio style subject submit success such suggest summary super supply support sure
surface switch symbol sync system table take talk target task team tell template temporary term test text than thank that their
them theme then there these thing think third this though thread three through ticket time timeout title today together token
tool top total touch track trade traffic train transfer transform trap tree trial trigger true trust try tunnel turn type under
union unique unit unknown until update upload upper usage use user using usual valid value variable vector version very video
view virtual visible visit voice volume wait wake walk wall want warm warning watch water wave way weak web week weight welcome
well what when where whether which while white whole why wide width wild will window wire wish with within without word work
world worker would wrap write wrong year yellow yes yet young zero zone`

var (
	bigramOnce sync.Once
	bigramLogP [26][26]float64
)

func initBigrams() {
	var counts [26][26]float64
	var rows [26]float64
	for _, w := range strings.Fields(trainingWords) {
		for i := 0; i+1 < len(w); i++ {
			a, b := w[i]-'a', w[i+1]-'a'
			counts[a][b]++
			rows[a]++
		}
	}
	for a := range counts {
		for b := range counts[a] {
			bigramLogP[a][b] = math.Log((counts[a][b] + 0.5) / (rows[a] + 0.5*26))
		}
	}
}

// wordRuns are the stretches of letters in v that a person would read as a word or two: a camelCase
// hump is a break, and digits, underscores, dashes and dots are separators.
func wordRuns(v []byte) [][]byte {
	var out [][]byte
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= 4 {
			out = append(out, v[start:end])
		}
		start = -1
	}
	for i, c := range v {
		isLetter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !isLetter {
			flush(i)
			continue
		}
		// a lower-case letter followed by an upper-case one starts a new hump
		if start >= 0 && c >= 'A' && c <= 'Z' && v[i-1] >= 'a' && v[i-1] <= 'z' {
			flush(i)
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(v))
	return out
}

// wordyBar is the mean log probability per letter pair above which a run of letters reads as words. Measured
// on words the model was not taught: they score about -2.5 at the median and -3.15 at the tenth percentile;
// random letters score -4.2 at the median and -3.5 at the ninetieth, because a pair never seen costs a lot.
// At this bar 91% of two- and three-word compounds read as words and 1 in 2,000 random strings does.
const wordyBar = -3.45

// Wordy says whether most of the letters of v sit in runs that read like words. It is the scorer that stands in
// for the token-efficiency test of the reference engine, whose data is not ours: a score from letter pairs
// learned from trainingWords.
func Wordy(v []byte) bool {
	if len(v) < 8 {
		return false
	}
	bigramOnce.Do(initBigrams)
	letters, wordy := 0, 0
	for _, c := range v {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			letters++
		}
	}
	for _, run := range wordRuns(v) {
		sum := 0.0
		for i := 0; i+1 < len(run); i++ {
			sum += bigramLogP[run[i]|0x20-'a'][run[i+1]|0x20-'a']
		}
		if sum/float64(len(run)-1) >= wordyBar {
			wordy += len(run)
		}
	}
	return letters >= 8 && float64(wordy) >= 0.7*float64(letters)
}
