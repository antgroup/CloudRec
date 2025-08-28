package cloudrec_7000001
import rego.v1
import data

default risk := false
risk if {
	has_public_address
	count(security_groups_misconfig) != 0
}
messages contains message if {
	risk == true
	message := {
		"Description": "SecurityGroup has a misconfiguration of ingress SourceIP",
		"Misconfig": security_groups_misconfig,
	}
}

public_ip_address := input.Instance.PublicIpAddress.IpAddress
has_public_address if {
    count(public_ip_address) > 0
}

security_groups_misconfig contains misconfig_sg_info if {
	some sg in input.SecurityGroups
	sg_id := sg.SecurityGroup.SecurityGroupId
	sg_name := sg.SecurityGroup.SecurityGroupName

	some sg_rule in sg.Permissions
	cidr := sg_rule.SourceCidrIp
    acl_ip_is_special_purpose_address(cidr) == false
	parts := split(cidr, "/")
	size := to_number(parts[1])
	size <= 8
	sg_rule.Direction == "ingress"
	sg_rule.Policy == "Accept"

	misconfig_sg_info := {
		"SecurityGroupId": sg_id,
		"SecurityGroupName": sg_name,
		"Misconfig": sg_rule,
	}
}

acl_ip_is_special_purpose_address(acl_ip) := true if {
    count(net.cidr_contains_matches(data.special_purpose_cidr.cidr_list, acl_ip)) > 0
}else := false