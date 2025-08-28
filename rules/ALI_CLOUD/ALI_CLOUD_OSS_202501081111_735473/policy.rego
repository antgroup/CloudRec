package cloudrec_3600007

import rego.v1

default risk := false

risk if {
	count(inventory_configurations) > 0
}

inventory_configurations contains inventory_configuration if {
	some _inventory_configuration in input.InventoryConfiguration
	destination_bucket_acs := split(_inventory_configuration.OSSBucketDestination.Bucket, ":")
	destination_bucket := destination_bucket_acs[count(destination_bucket_acs) - 1]
	inventory_configuration := sprintf(
		"Account %v: [%v.%v/%v] --> [%v.%v/%v/%v/%v/]",
		[
			_inventory_configuration.OSSBucketDestination.AccountId,
			input.BucketInfo.Name,
			input.BucketInfo.ExtranetEndpoint,
			_inventory_configuration.Prefix,
			destination_bucket,
			input.BucketInfo.ExtranetEndpoint,
			_inventory_configuration.OSSBucketDestination.Prefix,
			input.BucketInfo.Name,
			_inventory_configuration.Id,
		],
	)
}
