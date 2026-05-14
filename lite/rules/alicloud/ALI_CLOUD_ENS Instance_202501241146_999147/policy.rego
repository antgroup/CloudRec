package ens_instance_didnt_install_aegis_5600001

import rego.v1

default risk := false

risk if {
	agent := input.InstanceInstalledAegis
	agent_not_healthy(agent)
}

agent_not_healthy(agent) if {
	status := lower(agent.Instance.ClientStatus)
	status == "offline"
}

agent_not_healthy(agent) if {
	sub_status := lower(agent.Instance.ClientSubStatus)
	sub_status in {"offline", "uninstalled", "not_installed", "not installed"}
}
