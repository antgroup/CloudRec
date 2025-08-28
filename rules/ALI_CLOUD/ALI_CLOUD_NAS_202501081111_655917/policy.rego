package nas_exposed_to_public_3200002
import rego.v1

default risk := false

risk if {
    is_classic_network_type
}

is_classic_network_type if {
    input.FileSystem.MountTargets.MountTarget[_].NetworkType == "classic"
}

