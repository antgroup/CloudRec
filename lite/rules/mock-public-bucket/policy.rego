package cloudrec.lite.rules.mock_public_bucket

import rego.v1

findings contains finding if {
	input.provider == "mock"
	input.type == "storage_bucket"
	input.attributes.public == true

	finding := {
		"risk": "public_exposure",
		"asset_id": input.id,
		"asset_type": input.type,
		"account_id": input.account_id,
		"region": input.region,
		"title": sprintf("Public bucket: %s", [input.name]),
		"message": "Storage bucket allows public access.",
		"evidence": {
			"name": input.name,
			"public": input.attributes.public,
		},
	}
}
