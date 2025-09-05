package cloudrec_7600001

import rego.v1

default risk := false

risk if {
	count(msg) > 0
}

msg contains info if {
	addon_infos := json.unmarshal(input.Cluster.meta_data)
	some addon in addon_infos.Addons
	addon.name == "nginx-ingress-controller"

	# nginx-ingress-controller version less than v1.11.5-aliyun.1 is vulnerable to CVE-2025-1974 (IngressNightmare)
    standard_version := regex.find_n(`(\d+\.\d+\.\d+)`, addon.version, 1)[0]
	result := semver.compare("1.11.5-aliyun.1", standard_version)
	result == 1
	info := addon
}

