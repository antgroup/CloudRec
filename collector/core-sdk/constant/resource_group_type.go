// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package constant

type ResourceGroupType string

// Enum values for ResourceGroupType
const (
	NET        string = "NET"        // network service
	CONTAINER  string = "CONTAINER"  // container service
	DATABASE   string = "DATABASE"   // database service
	STORE      string = "STORE"      // store service
	COMPUTE    string = "COMPUTE"    // compute service
	IDENTITY   string = "IDENTITY"   // identity
	CONFIG     string = "CONFIG"     // config
	SECURITY   string = "SECURITY"   // security products
	AI         string = "AI"         // AI service
	MIDDLEWARE string = "MIDDLEWARE" // middleware service
	BIGDATA    string = "BIGDATA"    // big data service
	LOG        string = "LOG"        // log
	GOVERNANCE string = "GOVERNANCE" // cloud governance
	MONITORING string = "MONITORING" // monitor
)
