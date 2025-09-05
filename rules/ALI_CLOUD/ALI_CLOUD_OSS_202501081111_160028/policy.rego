package cloudrec_3600004
import rego.v1

default risk := false
# input.RefererConfiguration.RefererList value cloud be list
risk if {
	"*" in input.RefererConfiguration.RefererList
}
# input.RefererConfiguration.RefererList value cloud be string
risk if {
	input.RefererConfiguration.RefererList == "*"
}
