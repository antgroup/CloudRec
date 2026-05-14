package cloudrec_9000001

import rego.v1

default risk = false

risk if {
    count(input.TrailList) = 0
}