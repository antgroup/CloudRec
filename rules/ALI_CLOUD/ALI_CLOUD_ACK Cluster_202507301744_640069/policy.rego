package cloudrec_11200001

import rego.v1

default risk := false

risk if {
    has_internet_endpoint
    count(opened_ports) > 0
}

messages contains message if {
	risk == true
    message := {
        "Description": "全网开放ACK API Server",
        "API Server": json.unmarshal(input.Cluster.master_url).api_server_endpoint
    }
}

has_internet_endpoint if {
    master_url := json.unmarshal(input.Cluster.master_url)
    master_url.api_server_endpoint != ""
}

# AclStatus set to 'off'
opened_ports contains {port: reason} if {
	some listener in input.LoadBalancer[0].Listeners
	listener.Listener.ListenerPort == 6443
	listener.Listener.AclStatus == "off"

	port := listener.Listener.ListenerPort
	reason := "AclStatus set to 'off'"
}

# AclList config contains '0.0.0.0/0'
opened_ports contains {port: reason} if {
	some listener in input.LoadBalancer[0].Listeners
	listener.Listener.ListenerPort == 6443
	listener.Listener.AclType == "white"
	some acl in listener.AclList[_].AclEntrys[_]
	acl.AclEntryIP == "0.0.0.0/0"

	port := listener.Listener.ListenerPort
	reason := "AclList config contains '0.0.0.0/0'"
}
