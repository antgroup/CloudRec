package cloudrec_3600005

import rego.v1

default risk := false

risk if {
	some CORSRule in input.CORSConfiguration.CORSRules
	"*" in CORSRule.AllowedOrigin
}
