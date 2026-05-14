package ali_cloud_versioning_enable_6500006
import rego.v1

default risk := false
risk if {
    versioningConfig == null
}
risk if {
    versioningConfig.Status != "Enabled"
}

versioningConfig := input.VersioningConfig