package alicloud

import "testing"

func TestResourceSpecByTypeMatchesRuleStyleAssetType(t *testing.T) {
	spec, ok := ResourceSpecByType("oss")
	if !ok {
		t.Fatal("ResourceSpecByType(oss) was not found")
	}
	if spec.Type != "OSS" || spec.Group != "STORE" || spec.Dimension != DimensionGlobal {
		t.Fatalf("OSS spec = %#v", spec)
	}
}

func TestNormalizeResourceTypeKeepsAcronymsReadable(t *testing.T) {
	cases := map[string]string{
		"ECS":            "ecs",
		"SLB":            "slb",
		"RAM User":       "ram_user",
		"RAMUser":        "ram_user",
		"MongoDB":        "mongo_db",
		"Security Group": "security_group",
	}
	for input, want := range cases {
		if got := normalizeResourceType(input); got != want {
			t.Fatalf("normalizeResourceType(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNativeAdapterResourceTypesIncludesDefaultAdapters(t *testing.T) {
	types := NativeAdapterResourceTypes()
	if !containsResourceType(types, "OSS") {
		t.Fatalf("native adapter types missing OSS: %#v", types)
	}
	if !containsResourceType(types, "Account") {
		t.Fatalf("native adapter types missing Account: %#v", types)
	}
}

func containsResourceType(types []string, want string) bool {
	for _, resourceType := range types {
		if resourceType == want {
			return true
		}
	}
	return false
}
