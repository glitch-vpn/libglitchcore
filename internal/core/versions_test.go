package core

import (
	"encoding/json"
	"testing"
)

func TestVersionsJSONReportsCoreVersion(t *testing.T) {
	previous := builtCoreVersion
	t.Cleanup(func() { builtCoreVersion = previous })

	SetBuiltVersions("v9.8.7", "", "")
	var versions map[string]string
	if err := json.Unmarshal([]byte(VersionsJSON()), &versions); err != nil {
		t.Fatal(err)
	}
	if versions["core"] != "v9.8.7" {
		t.Fatalf("core = %q, want v9.8.7", versions["core"])
	}
}
