package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadManifestFileAcceptsCanonicalManifest(t *testing.T) {
	t.Parallel()
	signed := signedManifest(t)
	path := writeFixture(t, manifestJSON(t, signed))
	loaded, err := LoadManifestFile(path, defaultLoadOptions())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want, _ := signed.DigestHex()
	got, _ := loaded.DigestHex()
	if got != want {
		t.Fatalf("loaded digest %s, want %s", got, want)
	}
	if loaded.Signature == nil || !bytes.Equal(loaded.Signature.Value, signed.Signature.Value) {
		t.Fatal("signature did not round-trip")
	}
}

func TestLoadManifestFileRequiresOptions(t *testing.T) {
	t.Parallel()
	path := writeFixture(t, manifestJSON(t, signedManifest(t)))
	opts := defaultLoadOptions()
	opts.NodePublicKey = nil
	if _, err := LoadManifestFile(path, opts); loadCode(t, err) != ReasonOptionsInvalid {
		t.Fatalf("missing key accepted: %v", err)
	}
	opts = defaultLoadOptions()
	opts.ExpectedNodeID = ""
	if _, err := LoadManifestFile(path, opts); loadCode(t, err) != ReasonOptionsInvalid {
		t.Fatalf("missing node id accepted: %v", err)
	}
}

func TestLoadManifestFileRejectsMissingAndDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := LoadManifestFile(filepath.Join(dir, "absent.json"), defaultLoadOptions()); loadCode(t, err) != ReasonFileOpen {
		t.Fatalf("absent file: %v", err)
	}
	_, err := LoadManifestFile(dir, defaultLoadOptions())
	if code := loadCode(t, err); code != ReasonFileType && code != ReasonFileOpen {
		t.Fatalf("directory: %v", err)
	}
}

func TestLoadManifestFileRejectsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, manifestJSON(t, signedManifest(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	_, err := LoadManifestFile(link, defaultLoadOptions())
	if code := loadCode(t, err); code != ReasonFileType && code != ReasonFileOpen {
		t.Fatalf("symlink was followed: %v", err)
	}
}

func TestLoadManifestFileRejectsOversize(t *testing.T) {
	t.Parallel()
	data := manifestJSON(t, signedManifest(t))
	padded := append(data[:len(data)-1:len(data)-1], []byte(`,"attestationRef":"`)...)
	padded = append(padded, bytes.Repeat([]byte("a"), MaxManifestBytes)...)
	padded = append(padded, []byte(`"}`)...)
	path := writeFixture(t, padded)
	if _, err := LoadManifestFile(path, defaultLoadOptions()); loadCode(t, err) != ReasonFileOversize {
		t.Fatalf("oversize accepted: %v", err)
	}
}

func TestLoadManifestFileRejectsExactlyOverLimitViaLimitReader(t *testing.T) {
	t.Parallel()
	// One byte over the limit must be rejected by both the file loader and the
	// byte loader.
	data := bytes.Repeat([]byte(" "), MaxManifestBytes+1)
	path := writeFixture(t, data)
	if _, err := LoadManifestFile(path, defaultLoadOptions()); loadCode(t, err) != ReasonFileOversize {
		t.Fatalf("limit+1 accepted: %v", err)
	}
	_, err := loadManifestBytes(data, testNodeID, defaultLoadOptions().NodePublicKey, testNow)
	if loadCode(t, err) != ReasonFileOversize {
		t.Fatalf("byte loader accepted limit+1: %v", err)
	}
}

func hostileJSONCases(t testing.TB) map[string]struct {
	data []byte
	code string
} {
	t.Helper()
	signed := signedManifest(t)
	canonical := manifestJSON(t, signed)
	withoutBrace := canonical[:len(canonical)-1]
	bidi := string([]rune{0x202e})
	zeroWidth := string([]rune{0x200b})
	c1 := string([]rune{0x85})
	return map[string]struct {
		data []byte
		code string
	}{
		"trailing object":     {append(append([]byte{}, canonical...), []byte(`{}`)...), ReasonJSONTrailing},
		"trailing scalar":     {append(append([]byte{}, canonical...), []byte(` 1`)...), ReasonJSONTrailing},
		"trailing garbage":    {append(append([]byte{}, canonical...), []byte(`x`)...), ReasonJSONTrailing},
		"unknown field":       {append(append([]byte{}, withoutBrace...), []byte(`,"extra":1}`)...), ReasonJSONUnknownField},
		"unknown nested":      {bytes.Replace(canonical, []byte(`"probeDigest"`), []byte(`"bogus":1,"probeDigest"`), 1), ReasonJSONUnknownField},
		"duplicate key":       {append(append([]byte{}, withoutBrace...), []byte(`,"revision":7}`)...), ReasonJSONDuplicateKey},
		"duplicate nested":    {bytes.Replace(canonical, []byte(`"probeDigest"`), []byte(`"key":"x","probeDigest"`), 1), ReasonJSONDuplicateKey},
		"deep nesting":        {append(append([]byte{}, withoutBrace...), []byte(`,"x":[[[[[[[[[1]]]]]]]]]}`)...), ReasonJSONNesting},
		"bidi in value":       {bytes.Replace(canonical, []byte(testNodeID), []byte("node"+bidi+"0001"), 1), ReasonJSONString},
		"bidi escaped":        {bytes.Replace(canonical, []byte(testNodeID), []byte(`node\u202e0001`), 1), ReasonJSONString},
		"zero width in key":   {bytes.Replace(canonical, []byte(`"nodeId"`), []byte(`"node`+zeroWidth+`Id"`), 1), ReasonJSONString},
		"control in value":    {bytes.Replace(canonical, []byte(testNodeID), []byte(`node\u00010001`), 1), ReasonJSONString},
		"c1 in value":         {bytes.Replace(canonical, []byte(testNodeID), []byte("node"+c1), 1), ReasonJSONString},
		"del in value":        {bytes.Replace(canonical, []byte(testNodeID), []byte("node"+string(rune(0x7f))), 1), ReasonJSONString},
		"invalid utf8":        {bytes.Replace(canonical, []byte(testNodeID), []byte("node\xff"), 1), ReasonJSONString},
		"not an object":       {[]byte(`[]`), ReasonJSONSyntax},
		"null":                {[]byte(`null`), ReasonJSONSyntax},
		"empty":               {[]byte(``), ReasonJSONSyntax},
		"truncated":           {withoutBrace, ReasonJSONSyntax},
		"wrong type":          {bytes.Replace(canonical, []byte(`"revision":7`), []byte(`"revision":"7"`), 1), ReasonJSONSyntax},
		"negative revision":   {bytes.Replace(canonical, []byte(`"revision":7`), []byte(`"revision":-1`), 1), ReasonJSONSyntax},
		"schema version":      {bytes.Replace(canonical, []byte(`"schemaVersion":1,"nodeId"`), []byte(`"schemaVersion":2,"nodeId"`), 1), ReasonSchema},
		"digest tamper":       {bytes.Replace(canonical, []byte(`"isolated-table-only"`), []byte(`"isolated-table-only-x"`), 1), ReasonSchema},
		"wrong node id":       {manifestJSON(t, signedAs(t, "node-0002")), ReasonNodeMismatch},
		"tampered signature":  {tamperSignature(t, signed), ReasonSignatureInvalid},
		"unsigned":            {manifestJSON(t, testManifest(t)), ReasonSignatureInvalid},
		"foreign signer":      {manifestJSON(t, signedWithKey(t, 2)), ReasonSignatureInvalid},
		"expired":             {manifestJSON(t, expiredManifest(t)), ReasonExpired},
		"revision tampered":   {bytes.Replace(canonical, []byte(`"revision":7`), []byte(`"revision":8`), 1), ReasonSignatureInvalid},
		"entry key tampered":  {reorderEntries(t), ReasonSchema},
		"policy key tampered": {bytes.Replace(canonical, []byte(`"policyKeyId":"policy-key-1"`), []byte(`"policyKeyId":"policy-key-2"`), 1), ReasonSignatureInvalid},
	}
}

func TestLoadManifestFileHostileInputs(t *testing.T) {
	t.Parallel()
	for name, testCase := range hostileJSONCases(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := writeFixture(t, testCase.data)
			manifest, err := LoadManifestFile(path, defaultLoadOptions())
			if err == nil {
				t.Fatalf("hostile input accepted: %+v", manifest)
			}
			if code := loadCode(t, err); code != testCase.code {
				t.Fatalf("code %s, want %s (%v)", code, testCase.code, err)
			}
		})
	}
}

// TestLoadOrderNodeBindingBeforeSignature is order-sensitive: a manifest that
// is correctly signed by another node's key must be reported as a node
// mismatch, never as a signature failure, because the loader only ever holds
// the expected node's public key and must not reveal which check would have
// passed under a different key.
func TestLoadOrderNodeBindingBeforeSignature(t *testing.T) {
	t.Parallel()
	foreign := testManifest(t)
	foreign.NodeID = "node-0002"
	_, foreignKey := testKey(2)
	if err := foreign.Sign(foreignKey); err != nil {
		t.Fatal(err)
	}
	path := writeFixture(t, manifestJSON(t, foreign))
	_, err := LoadManifestFile(path, defaultLoadOptions())
	if code := loadCode(t, err); code != ReasonNodeMismatch {
		t.Fatalf("code %s, want %s: signature check ran before node binding", code, ReasonNodeMismatch)
	}
	// And a manifest for the right node with a bad signature is a signature
	// failure, not a node mismatch.
	path = writeFixture(t, tamperSignature(t, signedManifest(t)))
	_, err = LoadManifestFile(path, defaultLoadOptions())
	if code := loadCode(t, err); code != ReasonSignatureInvalid {
		t.Fatalf("code %s, want %s", code, ReasonSignatureInvalid)
	}
}

func TestLoadOrderSignatureBeforeExpiry(t *testing.T) {
	t.Parallel()
	expired := expiredManifest(t)
	expired.Signature.Value[0] ^= 0x01
	path := writeFixture(t, manifestJSON(t, expired))
	_, err := LoadManifestFile(path, defaultLoadOptions())
	if code := loadCode(t, err); code != ReasonSignatureInvalid {
		t.Fatalf("code %s, want %s: expiry must not mask a bad signature", code, ReasonSignatureInvalid)
	}
}

func TestLoadManifestFileExpiryUsesOptionsNow(t *testing.T) {
	t.Parallel()
	path := writeFixture(t, manifestJSON(t, signedManifest(t)))
	opts := defaultLoadOptions()
	opts.Now = testNow.Add(2 * time.Hour)
	if _, err := LoadManifestFile(path, opts); loadCode(t, err) != ReasonExpired {
		t.Fatalf("expired manifest accepted: %v", err)
	}
	opts.Now = testNow.Add(-time.Hour)
	if _, err := LoadManifestFile(path, opts); loadCode(t, err) != ReasonNotYetValid {
		t.Fatalf("future manifest accepted: %v", err)
	}
}

func TestLoadManifestFileDetectsSameSizeRewrite(t *testing.T) {
	t.Parallel()
	original := manifestJSON(t, signedManifest(t))
	path := writeFixture(t, original)
	// Same length, different bytes: flip one hex digit of the probe digest.
	rewritten := bytes.Replace(original, []byte(`"revision":7`), []byte(`"revision":8`), 1)
	if len(rewritten) != len(original) {
		t.Fatal("fixture bug: rewrite changed the length")
	}
	opts := defaultLoadOptions()
	opts.betweenReads = func() {
		if err := os.WriteFile(path, rewritten, 0o600); err != nil {
			t.Fatal(err)
		}
		// Force a visible mtime change even on coarse-granularity file systems.
		if err := os.Chtimes(path, testNow, testNow.Add(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := LoadManifestFile(path, opts)
	if code := loadCode(t, err); code != ReasonFileChanged {
		t.Fatalf("same-size rewrite not detected: %v", err)
	}
}

func TestLoadManifestFileDetectsReplacementByRename(t *testing.T) {
	t.Parallel()
	original := manifestJSON(t, signedManifest(t))
	path := writeFixture(t, original)
	opts := defaultLoadOptions()
	opts.betweenReads = func() {
		replacement := filepath.Join(filepath.Dir(path), "replacement.json")
		if err := os.WriteFile(replacement, original, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Skipf("rename over open file unsupported: %v", err)
		}
	}
	// The open descriptor still refers to the original inode, so the loader
	// either sees an unchanged identity (the read bytes are the original and
	// remain authentic) or detects a change. Both are safe; what must never
	// happen is a successful load of bytes that were not read.
	manifest, err := LoadManifestFile(path, opts)
	if err != nil {
		if loadCode(t, err) != ReasonFileChanged {
			t.Fatalf("unexpected failure: %v", err)
		}
		return
	}
	if manifest.NodeID != testNodeID {
		t.Fatal("loaded manifest is not the one that was read")
	}
}

func TestLoadManifestFileDetectsPartialRead(t *testing.T) {
	t.Parallel()
	original := manifestJSON(t, signedManifest(t))
	path := writeFixture(t, original)
	opts := defaultLoadOptions()
	opts.afterOpen = func() {
		// Truncate after the first stat so the read returns fewer bytes than
		// the stat size promised.
		if err := os.Truncate(path, int64(len(original)/2)); err != nil {
			t.Skipf("truncate of open file unsupported: %v", err)
		}
	}
	_, err := LoadManifestFile(path, opts)
	if code := loadCode(t, err); code != ReasonFileChanged {
		t.Fatalf("partial read not detected: %v", err)
	}
}

func TestLoadManifestFileDetectsGrowthDuringRead(t *testing.T) {
	t.Parallel()
	original := manifestJSON(t, signedManifest(t))
	path := writeFixture(t, original)
	opts := defaultLoadOptions()
	opts.afterOpen = func() {
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Skipf("append to open file unsupported: %v", err)
		}
		defer file.Close()
		if _, err := file.Write([]byte(" ")); err != nil {
			t.Fatal(err)
		}
	}
	_, err := LoadManifestFile(path, opts)
	if code := loadCode(t, err); code != ReasonFileChanged {
		t.Fatalf("growth during read not detected: %v", err)
	}
}

func TestLoadErrorNeverContainsFileContent(t *testing.T) {
	t.Parallel()
	secret := "SECRET-MARKER-DO-NOT-LEAK"
	for name, testCase := range hostileJSONCases(t) {
		data := bytes.Replace(testCase.data, []byte(`"driverVersion":"0.1.0"`), []byte(`"driverVersion":"`+secret+`"`), 1)
		path := writeFixture(t, data)
		_, err := LoadManifestFile(path, defaultLoadOptions())
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error text leaks file content: %v", name, err)
		}
	}
}

func TestPrescanJSONStateMachine(t *testing.T) {
	t.Parallel()
	accept := []string{
		`{}`, `{"a":1}`, `{"a":{"a":1},"b":[{"a":1},{"a":2}]}`, `{"a":[1,[2,[3,[4,[5,[6,[7]]]]]]]}`, `{"a":"b c"}`,
		`{"a":"` + string(rune(0xe9)) + `"}`, ` {"a":1} `,
	}
	for _, input := range accept {
		if err := prescanJSON([]byte(input)); err != nil {
			t.Errorf("%s rejected: %v", input, err)
		}
	}
	reject := map[string]string{
		`{"a":1,"a":2}`:                       ReasonJSONDuplicateKey,
		`{"a":{"b":1,"b":2}}`:                 ReasonJSONDuplicateKey,
		`{"a":[[[[[[[[1]]]]]]]]}`:             ReasonJSONNesting,
		`{"a":1}{"b":2}`:                      ReasonJSONTrailing,
		`{"a":1} x`:                           ReasonJSONTrailing,
		`[{"a":1}]`:                           ReasonJSONSyntax,
		`"a"`:                                 ReasonJSONSyntax,
		`{"a":`:                               ReasonJSONSyntax,
		`{"a":"\u0007"}`:                      ReasonJSONString,
		`{"a` + string(rune(0x202e)) + `":1}`: ReasonJSONString,
		`{"a":"` + string(rune(0x9f)) + `"}`:  ReasonJSONString,
	}
	for input, want := range reject {
		err := prescanJSON([]byte(input))
		if err == nil {
			t.Errorf("%s accepted", input)
			continue
		}
		if code := loadCode(t, err); code != want {
			t.Errorf("%s: code %s, want %s", input, code, want)
		}
	}
}

func signedAs(t testing.TB, nodeID string) *Manifest {
	t.Helper()
	manifest := testManifest(t)
	manifest.NodeID = nodeID
	_, private := testKey(1)
	if err := manifest.Sign(private); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func signedWithKey(t testing.TB, seed byte) *Manifest {
	t.Helper()
	manifest := testManifest(t)
	_, private := testKey(seed)
	if err := manifest.Sign(private); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func expiredManifest(t testing.TB) *Manifest {
	t.Helper()
	probe := healthyProbe(enforceKey, "nftables")
	probe.ProbedAt = testNow.Add(-3 * time.Hour)
	probe.ExpiresAt = testNow.Add(-time.Hour)
	manifest := testManifest(t, probe)
	manifest.IssuedAt = testNow.Add(-2 * time.Hour)
	_, private := testKey(1)
	if err := manifest.Sign(private); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func tamperSignature(t testing.TB, manifest *Manifest) []byte {
	t.Helper()
	copied := *manifest
	copied.Signature = &Signature{KeyID: manifest.Signature.KeyID, Algorithm: manifest.Signature.Algorithm, Value: bytes.Clone(manifest.Signature.Value)}
	copied.Signature.Value[5] ^= 0x40
	return manifestJSON(t, &copied)
}

// reorderEntries renames one entry key under an otherwise intact manifest. The
// probe digest binds the key, so the entry fails digest validation before the
// manifest signature is even consulted.
func reorderEntries(t testing.TB) []byte {
	t.Helper()
	manifest := signedManifest(t, healthyProbe("a.one", "nftables"), healthyProbe("b.two", "nftables"))
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(manifestJSON(t, manifest), &generic); err != nil {
		t.Fatal(err)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(generic["capabilities"], &entries); err != nil {
		t.Fatal(err)
	}
	// Swap the two entries' keys (content change under the same signature).
	entries[0] = bytes.Replace(entries[0], []byte(`"a.one"`), []byte(`"a.two"`), 1)
	swapped, _ := json.Marshal(entries)
	generic["capabilities"] = swapped
	data, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLoadManifestFileEntryOrderDoesNotBreakSignature(t *testing.T) {
	t.Parallel()
	manifest := signedManifest(t, healthyProbe("a.one", "nftables"), healthyProbe("b.two", "nftables"))
	manifest.Capabilities[0], manifest.Capabilities[1] = manifest.Capabilities[1], manifest.Capabilities[0]
	path := writeFixture(t, manifestJSON(t, manifest))
	if _, err := LoadManifestFile(path, defaultLoadOptions()); err != nil {
		t.Fatalf("reordered entries failed to load: %v", err)
	}
}

func FuzzLoadManifest(f *testing.F) {
	f.Add(manifestJSON(f, signedManifest(f)))
	for _, testCase := range hostileJSONCases(f) {
		f.Add(testCase.data)
	}
	public, _ := testKey(1)
	f.Fuzz(func(t *testing.T, data []byte) {
		manifest, err := loadManifestBytes(data, testNodeID, public, testNow)
		if err != nil {
			var loadErr *LoadError
			if !errors.As(err, &loadErr) || !strings.HasPrefix(loadErr.Code, "AF-CAP-") {
				t.Fatalf("untyped loader error: %v", err)
			}
			return
		}
		if manifest.NodeID != testNodeID {
			t.Fatal("accepted a manifest for another node")
		}
		if err := manifest.Verify(public); err != nil {
			t.Fatalf("accepted manifest does not verify: %v", err)
		}
		if !testNow.Before(manifest.ExpiresAt) {
			t.Fatal("accepted an expired manifest")
		}
	})
}
