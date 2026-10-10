# TLS certificates for cloud collectors

Cloud collectors verify the certificate chain and hostname before sending signed HTTPS requests. Alibaba Cloud public/private collection and Huawei Cloud collection use their SDKs' standard TLS verification. TLS errors stop the request; there is no fallback that disables verification.

For a private cloud endpoint, use HTTPS, a certificate whose subject alternative name matches the configured hostname, and a CA trusted by the collector runtime. Fix an expired certificate or a hostname mismatch at the endpoint.

On Linux, an explicitly managed PEM CA bundle can be supplied through Go's standard trust configuration. The bundle must include all roots needed by that collector; use the operator-approved trust bundle and restrict who can modify it.

```sh
SSL_CERT_FILE=/path/to/trusted-ca-bundle.pem ./collector-binary
```

The path and binary name above are placeholders. Use the same trust configuration in the actual service/container environment. For another operating system, install the approved CA in the runtime's supported certificate store. A CA bundle does not waive hostname verification.

The local regression tests use disposable loopback servers and placeholder signing credentials. They cover a valid chain, an untrusted certificate and an incorrect hostname, and verify that a rejected peer receives no signed HTTP request. Cloud endpoint reachability, real credentials and the deployment's CA inventory still require an operator check before rollout.
