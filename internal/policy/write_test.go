package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseWriteModes(t *testing.T) {
	cases := map[string]WritePolicy{
		"create":                   {AllowCreate: true},
		"add-fields":               {AllowAddFields: true},
		"update":                   {AllowUpdate: true},
		"create,add-fields":        {AllowCreate: true, AllowAddFields: true},
		" create , add-fields ":    {AllowCreate: true, AllowAddFields: true},
		"create,add-fields,update": {AllowCreate: true, AllowAddFields: true, AllowUpdate: true},
		"both":                     {AllowCreate: true, AllowUpdate: true}, // legacy spelling
		"none":                     {},
	}
	for in, want := range cases {
		got, err := ParseWriteModes(in)
		if err != nil || got != want {
			t.Errorf("ParseWriteModes(%q) = %+v, %v; want %+v", in, got, err, want)
		}
		// String is the inverse: what `sb list` prints can be fed back.
		back, err := ParseWriteModes(got.String())
		if err != nil || back != got {
			t.Errorf("round trip of %q via %q gave %+v, %v", in, got.String(), back, err)
		}
	}
	for _, bad := range []string{"", "add_fields", "create,", "write", "all"} {
		if _, err := ParseWriteModes(bad); err == nil {
			t.Errorf("ParseWriteModes(%q) should fail", bad)
		}
	}
}

// Update implies adding fields (overwriting is the stronger grant); add-fields
// never implies update, and neither implies create.
func TestWriteMode(t *testing.T) {
	if m := (WritePolicy{AllowAddFields: true}).Mode(); m.Update || m.Create || !m.AddFields {
		t.Errorf("add-fields mode = %+v", m)
	}
	if m := (WritePolicy{AllowUpdate: true}).Mode(); !m.AddFields || !m.Update || m.Create {
		t.Errorf("update mode = %+v", m)
	}
	if (WritePolicy{}).Mode().Any() {
		t.Error("an empty policy must permit no write")
	}
}

// A policy file written before add-fields existed still loads (as denied),
// and the new grant survives a save/load round trip.
func TestAddFieldsPersists(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.json")
	old := `{"items": [], "writes": {"keepass": {"allow_create": true, "allow_update": false}}}`
	if err := os.WriteFile(p, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.WriteAllow("keepass"); got != (WritePolicy{AllowCreate: true}) {
		t.Fatalf("legacy file loaded as %+v", got)
	}
	newer := `{"items": [], "writes": {"keepass": {"allow_create": true, "allow_update": false, "allow_add_fields": true}}}`
	if err := os.WriteFile(p, []byte(newer), 0600); err != nil {
		t.Fatal(err)
	}
	st, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.WriteAllow("keepass"); got != (WritePolicy{AllowCreate: true, AllowAddFields: true}) {
		t.Fatalf("add-fields not loaded: %+v", got)
	}
}

func TestRefuseUnknownFields(t *testing.T) {
	if err := RefuseUnknownFields("bw", map[string]string{"UserName": "u", "Password": "p", "URL": "x"},
		"UserName", "Password", "URL"); err != nil {
		t.Fatalf("supported fields refused: %v", err)
	}
	const seed = "GEZDGNBVGY3TQOJQ"
	err := RefuseUnknownFields("bw", map[string]string{"Password": "p", "otp": seed, "username": "u"},
		"UserName", "Password", "URL")
	if err == nil || !strings.Contains(err.Error(), "otp, username") || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("want a refusal naming otp and username, got %v", err)
	}
	if strings.Contains(err.Error(), seed) {
		t.Fatalf("refusal leaks a value: %v", err)
	}
}
