package ens_instance_didnt_install_aegis_5600001

import rego.v1

default risk := false

risk if {
	not installed
}

risk if {
	is_null(installed)
}

# The edition of Security Center that is authorized to scan the asset. Valid values:
#
# 	- **1**: Basic edition
#
# 	- **6**: Anti-virus edition
#
# 	- **5**: Advanced edition
#
# 	- **3**: Enterprise edition
#
# 	- **7**: Ultimate edition
#
# 	- **10**: Value-added Plan edition
#
# example:
#
# 3
risk if {
	installed.Instance.AuthVersion != 7
}

installed := input.InstanceInstalledAegis
