package enable_smb_acl_6800005
import rego.v1

default risk := false
risk if {
    input.SmbAcl.Enabled == false
}