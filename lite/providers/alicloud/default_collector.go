package alicloud

func NewDefaultCollector() Collector {
	native := NewRegistryCollector(
		WithResourceAdapter(NewOSSAdapter()),
		WithResourceAdapter(NewAccountAdapter()),
		WithResourceAdapter(NewRAMUserAdapter()),
		WithResourceAdapter(NewRAMRoleAdapter()),
		WithResourceAdapter(NewECSAdapter()),
		WithResourceAdapter(NewSecurityGroupAdapter()),
		WithResourceAdapter(NewSLBAdapter()),
		WithResourceAdapter(NewALBAdapter()),
		WithResourceAdapter(NewNLBAdapter()),
		WithResourceAdapter(NewRDSAdapter()),
		WithResourceAdapter(NewRedisAdapter()),
		WithResourceAdapter(NewMongoDBAdapter()),
	)
	return NewHybridCollector(native, NewLegacyCollector())
}

func NativeAdapterResourceTypes() []string {
	adapters := []ResourceAdapter{
		NewOSSAdapter(),
		NewAccountAdapter(),
		NewRAMUserAdapter(),
		NewRAMRoleAdapter(),
		NewECSAdapter(),
		NewSecurityGroupAdapter(),
		NewSLBAdapter(),
		NewALBAdapter(),
		NewNLBAdapter(),
		NewRDSAdapter(),
		NewRedisAdapter(),
		NewMongoDBAdapter(),
	}
	types := make([]string, 0, len(adapters))
	for _, adapter := range adapters {
		types = append(types, adapter.Spec().Type)
	}
	return types
}
