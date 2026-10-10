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

package collector

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
)

func TestSignedIAMRequestVerifiesTLSPeer(t *testing.T) {
	var accepted atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepted.Add(1)
		if r.Header.Get("Authorization") == "" {
			t.Error("SDK request did not include an authorization signature")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"users":[]}`)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	trusted := x509.NewCertPool()
	trusted.AddCert(server.Certificate())
	cases := []struct {
		name        string
		roots       *x509.CertPool
		serverName  string
		customTrust bool
		wantError   bool
	}{
		{name: "default configuration rejects untrusted certificate", wantError: true},
		{name: "explicit trusted certificate", roots: trusted, customTrust: true},
		{name: "untrusted certificate", roots: x509.NewCertPool(), customTrust: true, wantError: true},
		{name: "wrong hostname", roots: trusted, serverName: "wrong.example.invalid", customTrust: true, wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := getHttpConfig()
			if config.IgnoreSSLVerification {
				t.Fatal("collector disabled TLS verification")
			}
			if tc.customTrust {
				transport := &http.Transport{TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12, RootCAs: tc.roots, ServerName: tc.serverName,
				}}
				defer transport.CloseIdleConnections()
				config.WithHttpTransport(transport)
			}
			client, err := iam.IamClientBuilder().WithEndpoints([]string{server.URL}).
				WithCredential(ConfigGlobalAuth("placeholder-access-key", "placeholder-secret")).
				WithHttpConfig(config).SafeBuild()
			if err != nil {
				t.Fatal(err)
			}
			before := accepted.Load()
			_, err = iam.NewIamClient(client).KeystoneListUsers(&model.KeystoneListUsersRequest{})
			if tc.wantError {
				if err == nil {
					t.Fatal("expected TLS verification to reject the request")
				}
				if accepted.Load() != before {
					t.Fatal("rejected peer received the signed request")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if accepted.Load() != before+1 {
					t.Fatal("trusted peer did not receive the signed request")
				}
			}
		})
	}
}
