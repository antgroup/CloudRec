package example_12300001
import rego.v1

default risk := false

risk if {
    input.CloudfwVersionInfo.UserStatus == true
    input.CloudfwVersionInfo.LogStatus != true
}
