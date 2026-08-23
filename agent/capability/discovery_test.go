package capability

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DBarr3/AntiFlock/agent/driver"
)

func discoveryOptions(probers map[string]driver.Prober) Options {
	_, private := testKey(1)
	return Options{
		NodeID:      testNodeID,
		Revision:    3,
		PolicyKeyID: testPolicyKeyID,
		Probers:     probers,
		Now:         func() time.Time { return testNow },
		NodeKey:     private,
	}
}

func TestDiscoverProducesSignedNodeBoundManifest(t *testing.T) {
	t.Parallel()
	short := healthyProbe("dns.resolver.observe", "resolver")
	short.ExpiresAt = testNow.Add(10 * time.Minute)
	manifest, err := Discover(context.Background(), discoveryOptions(map[string]driver.Prober{
		"nftables": staticProber{results: []driver.ProbeResult{healthyProbe("firewall.nftables.enforce", "nftables")}},
		"resolver": staticProber{results: []driver.ProbeResult{short}},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if manifest.NodeID != testNodeID || manifest.Revision != 3 || manifest.PolicyKeyID != testPolicyKeyID {
		t.Fatalf("manifest header not bound to options: %+v", manifest)
	}
	if !manifest.IssuedAt.Equal(testNow) {
		t.Fatalf("issued-at %s is not the clock", manifest.IssuedAt)
	}
	if !manifest.ExpiresAt.Equal(short.ExpiresAt) {
		t.Fatalf("expires-at %s is not the earliest probe expiry %s", manifest.ExpiresAt, short.ExpiresAt)
	}
	if len(manifest.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(manifest.Capabilities))
	}
	public, _ := testKey(1)
	if err := manifest.Verify(public); err != nil {
		t.Fatalf("discovered manifest does not verify: %v", err)
	}
	for _, entry := range manifest.Capabilities {
		if err := entry.Validate(); err != nil {
			t.Fatalf("entry %s: %v", entry.Key, err)
		}
	}
}

func TestDiscoverUnsignedWhenNoKey(t *testing.T) {
	t.Parallel()
	opts := discoveryOptions(map[string]driver.Prober{
		"nftables": staticProber{results: []driver.ProbeResult{healthyProbe("firewall.nftables.enforce", "nftables")}},
	})
	opts.NodeKey = nil
	opts.Revision = 0
	manifest, err := Discover(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Signature != nil || manifest.Revision != 1 {
		t.Fatalf("expected unsigned revision 1 manifest, got %+v", manifest)
	}
}

func TestDiscoverRejectsDuplicateKeyAcrossDrivers(t *testing.T) {
	t.Parallel()
	_, err := Discover(context.Background(), discoveryOptions(map[string]driver.Prober{
		"alpha": staticProber{results: []driver.ProbeResult{healthyProbe("firewall.enforce", "alpha")}},
		"beta":  staticProber{results: []driver.ProbeResult{healthyProbe("firewall.enforce", "beta")}},
	}))
	if code := discoveryCode(t, err); code != ReasonDuplicateKey {
		t.Fatalf("code %s, want %s", code, ReasonDuplicateKey)
	}
}

func TestDiscoverRejectsDuplicateKeyWithinDriver(t *testing.T) {
	t.Parallel()
	_, err := Discover(context.Background(), discoveryOptions(map[string]driver.Prober{
		"alpha": staticProber{results: []driver.ProbeResult{healthyProbe("firewall.enforce", "alpha"), healthyProbe("firewall.enforce", "alpha")}},
	}))
	if code := discoveryCode(t, err); code != ReasonDuplicateKey {
		t.Fatalf("code %s, want %s", code, ReasonDuplicateKey)
	}
}

func TestDiscoverRejectsDriverNameMismatch(t *testing.T) {
	t.Parallel()
	_, err := Discover(context.Background(), discoveryOptions(map[string]driver.Prober{
		"alpha": staticProber{results: []driver.ProbeResult{healthyProbe("firewall.enforce", "impostor")}},
	}))
	if code := discoveryCode(t, err); code != ReasonDriverMismatch {
		t.Fatalf("code %s, want %s", code, ReasonDriverMismatch)
	}
}

func TestDiscoverRejectsInvalidProbe(t *testing.T) {
	t.Parallel()
	bad := healthyProbe("firewall.enforce", "alpha")
	bad.ReasonCodes = nil
	_, err := Discover(context.Background(), discoveryOptions(map[string]driver.Prober{
		"alpha": staticProber{results: []driver.ProbeResult{bad}},
	}))
	if code := discoveryCode(t, err); code != ReasonProbeInvalid {
		t.Fatalf("code %s, want %s", code, ReasonProbeInvalid)
	}
	if !errors.Is(err, driver.ErrProbeInvalid) {
		t.Fatalf("error does not wrap driver.ErrProbeInvalid: %v", err)
	}
}

func TestDiscoverFailsClosedOnProberError(t *testing.T) {
	t.Parallel()
	_, err := Discover(context.Background(), discoveryOptions(map[string]driver.Prober{
		"alpha": staticProber{results: []driver.ProbeResult{healthyProbe("a.one", "alpha")}},
		"beta":  staticProber{err: errors.New("nft: raw output that must not leak")},
	}))
	if code := discoveryCode(t, err); code != ReasonProbeFailed {
		t.Fatalf("code %s, want %s", code, ReasonProbeFailed)
	}
	if text := err.Error(); strings.Contains(text, "raw output") {
		t.Fatalf("prober error text leaked: %s", text)
	}
}

func TestDiscoverBoundsProbeTimeout(t *testing.T) {
	t.Parallel()
	opts := discoveryOptions(map[string]driver.Prober{"slow": staticProber{block: true}})
	opts.ProbeTimeout = 20 * time.Millisecond
	started := time.Now()
	_, err := Discover(context.Background(), opts)
	if code := discoveryCode(t, err); code != ReasonProbeTimeout {
		t.Fatalf("code %s, want %s", code, ReasonProbeTimeout)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("discovery did not honour the probe timeout")
	}
}

func TestDiscoverAbandonsProberThatIgnoresContext(t *testing.T) {
	t.Parallel()
	opts := discoveryOptions(map[string]driver.Prober{"stuck": stuckProber{release: make(chan struct{})}})
	opts.ProbeTimeout = 20 * time.Millisecond
	_, err := Discover(context.Background(), opts)
	if code := discoveryCode(t, err); code != ReasonProbeTimeout {
		t.Fatalf("code %s, want %s", code, ReasonProbeTimeout)
	}
}

type stuckProber struct{ release chan struct{} }

func (prober stuckProber) Probe(context.Context) ([]driver.ProbeResult, error) {
	<-prober.release
	return nil, nil
}

type panicProber struct{}

func (panicProber) Probe(context.Context) ([]driver.ProbeResult, error) { panic("driver bug") }

func TestDiscoverContainsProberPanic(t *testing.T) {
	t.Parallel()
	_, err := Discover(context.Background(), discoveryOptions(map[string]driver.Prober{"boom": panicProber{}}))
	if code := discoveryCode(t, err); code != ReasonProbeFailed {
		t.Fatalf("code %s, want %s", code, ReasonProbeFailed)
	}
}

func TestDiscoverRejectsExpiredProbeAndEmptyDiscovery(t *testing.T) {
	t.Parallel()
	stale := healthyProbe("a.one", "alpha")
	stale.ProbedAt = testNow.Add(-2 * time.Hour)
	stale.ExpiresAt = testNow.Add(-time.Hour)
	_, err := Discover(context.Background(), discoveryOptions(map[string]driver.Prober{"alpha": staticProber{results: []driver.ProbeResult{stale}}}))
	if code := discoveryCode(t, err); code != ReasonExpired {
		t.Fatalf("code %s, want %s", code, ReasonExpired)
	}
	_, err = Discover(context.Background(), discoveryOptions(map[string]driver.Prober{"alpha": staticProber{}}))
	if code := discoveryCode(t, err); code != ReasonNoCapabilities {
		t.Fatalf("code %s, want %s", code, ReasonNoCapabilities)
	}
	_, err = Discover(context.Background(), discoveryOptions(nil))
	if code := discoveryCode(t, err); code != ReasonNoCapabilities {
		t.Fatalf("code %s, want %s", code, ReasonNoCapabilities)
	}
}

func TestDiscoverRejectsBadOptions(t *testing.T) {
	t.Parallel()
	probers := map[string]driver.Prober{"alpha": staticProber{results: []driver.ProbeResult{healthyProbe("a.one", "alpha")}}}
	cases := map[string]func(*Options){
		"empty node":      func(o *Options) { o.NodeID = "" },
		"empty policy":    func(o *Options) { o.PolicyKeyID = "" },
		"timeout too big": func(o *Options) { o.ProbeTimeout = MaxProbeTimeout + time.Second },
		"negative":        func(o *Options) { o.ProbeTimeout = -1 },
		"short key":       func(o *Options) { o.NodeKey = o.NodeKey[:10] },
		"nil prober":      func(o *Options) { o.Probers = map[string]driver.Prober{"alpha": nil} },
		"bad name":        func(o *Options) { o.Probers = map[string]driver.Prober{"al pha": probers["alpha"]} },
	}
	for name, mutate := range cases {
		opts := discoveryOptions(probers)
		mutate(&opts)
		_, err := Discover(context.Background(), opts)
		if code := discoveryCode(t, err); code != ReasonOptionsInvalid {
			t.Errorf("%s: code %s, want %s", name, code, ReasonOptionsInvalid)
		}
	}
	//lint:ignore SA1012 a nil context is the condition under test
	if _, err := Discover(nil, discoveryOptions(probers)); discoveryCode(t, err) != ReasonOptionsInvalid {
		t.Fatal("nil context accepted")
	}
}
