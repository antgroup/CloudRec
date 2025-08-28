package cloudrec_10700001

import rego.v1

default risk := false

risk if {
	input.Instance.MetadataOptions.HttpTokens != "required"
}

risk if {
	not input.Instance.MetadataOptions.HttpTokens
}
