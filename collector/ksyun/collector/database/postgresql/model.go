package postgresql

type DescribeDBInstanceParametersResponse struct {
	Data struct {
		EngineVersion *string `json:"EngineVersion" name:"EngineVersion"`
		Parameters    struct {
			AutovacuumAnalyzeScaleFactor *float64 `json:"autovacuum_analyze_scale_factor" name:"autovacuum_analyze_scale_factor"`
			LogTempFiles                 *int     `json:"log_temp_files" name:"log_temp_files"`
			AutovacuumVacuumThreshold    *int     `json:"autovacuum_vacuum_threshold" name:"autovacuum_vacuum_threshold"`
			VacuumFreezeTableAge         *int     `json:"vacuum_freeze_table_age" name:"vacuum_freeze_table_age"`
			AutovacuumFreezeMaxAge       *int     `json:"autovacuum_freeze_max_age" name:"autovacuum_freeze_max_age"`
			WalLevel                     *string  `json:"wal_level" name:"wal_level"`
			AutovacuumVacuumCostLimit    *int     `json:"autovacuum_vacuum_cost_limit" name:"autovacuum_vacuum_cost_limit"`
			AutovacuumVacuumScaleFactor  *float64 `json:"autovacuum_vacuum_scale_factor" name:"autovacuum_vacuum_scale_factor"`
			TrackActivityQuerySize       *int     `json:"track_activity_query_size" name:"track_activity_query_size"`
			AutovacuumMaxWorkers         *int     `json:"autovacuum_max_workers" name:"autovacuum_max_workers"`
			CheckpointTimeout            *int     `json:"checkpoint_timeout" name:"checkpoint_timeout"`
			WalKeepSegments              *int     `json:"wal_keep_segments" name:"wal_keep_segments"`
			AutovacuumVacuumCostDelay    *int     `json:"autovacuum_vacuum_cost_delay" name:"autovacuum_vacuum_cost_delay"`
			AutovacuumNaptime            *int     `json:"autovacuum_naptime" name:"autovacuum_naptime"`
			AutovacuumAnalyzeThreshold   *int     `json:"autovacuum_analyze_threshold" name:"autovacuum_analyze_threshold"`
			DefaultStatisticsTarget      *int     `json:"default_statistics_target" name:"default_statistics_target"`
			LogAutovacuumMinDuration     *int     `json:"log_autovacuum_min_duration" name:"log_autovacuum_min_duration"`
		} `json:"Parameters" name:"Parameters"`
	} `json:"Data"`
	RequestId *string `json:"RequestId" name:"RequestId"`
}

type DescribeDBInstancesResponse struct {
	Data struct {
		Instances []struct {
			DBInstanceClass struct {
				Id      *string `json:"Id" name:"Id"`
				Iops    *int    `json:"Iops" name:"Iops"`
				Vcpus   *int    `json:"Vcpus" name:"Vcpus"`
				Disk    *int    `json:"Disk" name:"Disk"`
				Ram     *int    `json:"Ram" name:"Ram"`
				Mem     *int    `json:"Mem" name:"Mem"`
				MaxConn *int    `json:"MaxConn" name:"MaxConn"`
			} `json:"DBInstanceClass"`
			DBInstanceIdentifier   *string `json:"DBInstanceIdentifier" name:"DBInstanceIdentifier"`
			DBInstanceName         *string `json:"DBInstanceName" name:"DBInstanceName"`
			DBInstanceStatus       *string `json:"DBInstanceStatus" name:"DBInstanceStatus"`
			DBInstanceType         *string `json:"DBInstanceType" name:"DBInstanceType"`
			DBParameterGroupId     *string `json:"DBParameterGroupId" name:"DBParameterGroupId"`
			PreferredBackupTime    *string `json:"PreferredBackupTime" name:"PreferredBackupTime"`
			GroupId                *string `json:"GroupId" name:"GroupId"`
			SecurityGroupId        *string `json:"SecurityGroupId" name:"SecurityGroupId"`
			Vip                    *string `json:"Vip" name:"Vip"`
			Port                   *int    `json:"Port" name:"Port"`
			Engine                 *string `json:"Engine" name:"Engine"`
			EngineVersion          *string `json:"EngineVersion" name:"EngineVersion"`
			InstanceCreateTime     *string `json:"InstanceCreateTime" name:"InstanceCreateTime"`
			MasterUserName         *string `json:"MasterUserName" name:"MasterUserName"`
			DatastoreVersionId     *string `json:"DatastoreVersionId" name:"DatastoreVersionId"`
			VpcId                  *string `json:"VpcId" name:"VpcId"`
			SubnetId               *string `json:"SubnetId" name:"SubnetId"`
			PubliclyAccessible     *bool   `json:"PubliclyAccessible" name:"PubliclyAccessible"`
			BillType               *string `json:"BillType" name:"BillType"`
			OrderType              *string `json:"OrderType" name:"OrderType"`
			MultiAvailabilityZone  *bool   `json:"MultiAvailabilityZone" name:"MultiAvailabilityZone"`
			MasterAvailabilityZone *string `json:"MasterAvailabilityZone" name:"MasterAvailabilityZone"`
			SlaveAvailabilityZone  *string `json:"SlaveAvailabilityZone" name:"SlaveAvailabilityZone"`
			AvailabilityZoneList   []struct {
				MemberType *string `json:"MemberType" name:"MemberType"`
				AzCode     *string `json:"AzCode" name:"AzCode"`
			} `json:"AvailabilityZoneList"`
			DiskUsed                         *int      `json:"DiskUsed" name:"DiskUsed"`
			Eip                              *string   `json:"Eip" name:"Eip"`
			EipPort                          *string   `json:"EipPort" name:"EipPort"`
			InnerAzCode                      *string   `json:"InnerAzCode" name:"InnerAzCode"`
			Audit                            *bool     `json:"Audit" name:"Audit"`
			ReadReplicaDBInstanceIdentifiers []*string `json:"ReadReplicaDBInstanceIdentifiers" name:"ReadReplicaDBInstanceIdentifiers"`
			ProductId                        *string   `json:"ProductId" name:"ProductId"`
			ProductWhat                      *int      `json:"ProductWhat" name:"ProductWhat"`
			ProjectId                        *int      `json:"ProjectId" name:"ProjectId"`
			ProjectName                      *string   `json:"ProjectName" name:"ProjectName"`
			Region                           *string   `json:"Region" name:"Region"`
			ServiceStartTime                 *string   `json:"ServiceStartTime" name:"ServiceStartTime"`
			SubOrderId                       *string   `json:"SubOrderId" name:"SubOrderId"`
			MiniVersion                      *string   `json:"MiniVersion" name:"MiniVersion"`
			SecurityGroups                   []struct {
				SecurityGroupId   *string `json:"SecurityGroupId" name:"SecurityGroupId"`
				SecurityGroupType *string `json:"SecurityGroupType" name:"SecurityGroupType"`
			} `json:"SecurityGroups"`
			NetworkType   *int      `json:"NetworkType" name:"NetworkType"`
			SupportIPV6   *bool     `json:"SupportIPV6" name:"SupportIPV6"`
			BindInstances []*string `json:"BindInstances" name:"BindInstances"`
			ProxyNodeInfo []*string `json:"ProxyNodeInfo" name:"ProxyNodeInfo"`
			ProxyInfo     []*string `json:"ProxyInfo" name:"ProxyInfo"`
			AutoSwitch    *int      `json:"AutoSwitch" name:"AutoSwitch"`
			BillTypeId    *int      `json:"BillTypeId" name:"BillTypeId"`
		} `json:"Instances" name:"Instances"`
	} `json:"Data"`
	RequestId *string `json:"RequestId" name:"RequestId"`
}
