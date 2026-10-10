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

package security

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
)

// Exercise signed SDK requests using disposable loopback TLS endpoints.
func TestSignedRequestVerifiesTLSPeer(t *testing.T) {
	var accepted atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepted.Add(1)
		if r.URL.Query().Get("Signature") == "" {
			t.Error("SDK request did not include a signature")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"RequestId":"local-test","Credentials":{"SecurityToken":"placeholder"}}`)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	trusted := x509.NewCertPool()
	trusted.AddCert(server.Certificate())
	cases := []struct {
		name       string
		roots      *x509.CertPool
		serverName string
		wantError  bool
	}{
		{name: "trusted certificate", roots: trusted},
		{name: "untrusted certificate", roots: x509.NewCertPool(), wantError: true},
		{name: "wrong hostname", roots: trusted, serverName: "wrong.example.invalid", wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := sdk.NewConfig().WithTimeout(2 * time.Second).WithAutoRetry(false)
			client, err := sdk.NewClientWithOptions("local-test", config,
				credentials.NewAccessKeyCredential("placeholder-access-key", "placeholder-secret"))
			if err != nil {
				t.Fatal(err)
			}
			client.SetNoProxy("127.*|localhost")
			transport := &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, RootCAs: tc.roots, ServerName: tc.serverName,
			}}
			defer transport.CloseIdleConnections()
			client.SetTransport(transport)
			request := requests.NewCommonRequest()
			request.Scheme = "HTTPS"
			request.Domain = strings.TrimPrefix(server.URL, "https://")
			request.Version = "2014-05-26"
			request.ApiName = "DescribeInstances"
			request.Method = "GET"
			request.QueryParams["InstanceIds"] = "[\"placeholder-instance\"]"
			before := accepted.Load()
			_, err = client.ProcessCommonRequest(request)
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
					t.Fatal("trusted peer did not receive the request")
				}
			}
			if transport.TLSClientConfig.InsecureSkipVerify {
				t.Fatal("SDK disabled peer verification")
			}
		})
	}
}
