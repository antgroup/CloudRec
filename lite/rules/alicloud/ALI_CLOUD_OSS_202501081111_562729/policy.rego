package cloudrec_2200003
import rego.v1

default risk := false

risk if {
    not isBlockPublicAccess
    acl := input.BucketInfo.ACL
    acl == "public-read"
}

isBlockPublicAccess if {
    input.BucketInfo.BlockPublicAccess == true
}

ACL:= input.BucketInfo.ACL
Name:=input.BucketInfo.Name