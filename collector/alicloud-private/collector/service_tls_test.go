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
	"strings"
	"sync/atomic"
	"testing"

	sdklog "github.com/core-sdk/log"
	"go.uber.org/zap"
)

// Exercise signed SDK requests using disposable loopback TLS endpoints.
func TestResourceGroupRequestVerifiesTLSPeer(t *testing.T) {
	previousLogger := sdklog.GetWLogger()
	sdklog.SetWLogger(zap.NewNop())
	t.Cleanup(func() { sdklog.SetWLogger(previousLogger) })
	var accepted atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepted.Add(1)
		if r.URL.Query().Get("Signature") == "" {
			t.Error("resource-group request did not include a signature")
		}
		if r.URL.Query().Get("Action") != "ListResourceGroup" {
			t.Error("unexpected business operation")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"successResponse":true,"data":[{"id":1,"organizationId":1}]}`)
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
			client, err := CreateBaseClient("local-test", strings.TrimPrefix(server.URL, "https://"),
				"placeholder-access-key", "placeholder-secret")
			if err != nil {
				t.Fatal(err)
			}
			client.SetNoProxy("127.*|localhost")
			transport := &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, RootCAs: tc.roots, ServerName: tc.serverName,
			}}
			defer transport.CloseIdleConnections()
			client.SetTransport(transport)
			before := accepted.Load()
			response := ListResourceGroup(client, strings.TrimPrefix(server.URL, "https://"))
			if tc.wantError {
				if len(response.Data) != 0 {
					t.Fatal("rejected request produced business data")
				}
				if accepted.Load() != before {
					t.Fatal("rejected peer received the signed request")
				}
			} else {
				if len(response.Data) != 1 || response.Data[0].Id != 1 {
					t.Fatal("trusted request did not produce expected resource-group data")
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
