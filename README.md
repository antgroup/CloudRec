<div align="center">
  <h1><img src="doc/images/logo.png" width="20"> CloudRec</h1>
  <p>
    <img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square">
    <a href="https://docs.cloudrec.cloud"><img src="https://img.shields.io/badge/doc-English-blue?style=flat-square"></a>
    <a href="https://cloudrec.yuque.com/org-wiki-cloudrec-iew3sz/hocvhx"><img src="https://img.shields.io/badge/文档-简体中文-blue?style=flat-square"></a>
    <a href="https://discord.gg/WpWT9Q8BkD"><img src="https://img.shields.io/badge/Disord-Join_CloudRec-brightgreen?logo=discord&style=flat-square" /></a>
    <a href="https://qr.dingtalk.com/action/joingroup?code=v1,k1,rsTf3mOAcQuKrY0//YlclWTUG4zcL9eQGsJIjjDj88A=&_dt_no_comment=1&origin=11"><img src="https://img.shields.io/badge/DingTalk-Join_CloudRec-brightgreen?logo=data:image/svg+xml;base64,PHN2ZyB0PSIxNzQ3NzIxMzEzNDg4IiBjbGFzcz0iaWNvbiIgdmlld0JveD0iMCAwIDEwMjQgMTAyNCIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHAtaWQ9IjcxMzgiIHdpZHRoPSIyMDAiIGhlaWdodD0iMjAwIj48cGF0aCBkPSJNOTA4LjQ3NCAzODEuOTJjLTEuNzY3IDcuNDctNi4xMjggMTguNDE5LTEyLjI0NiAzMS42MjRoMC4xMzJsLTAuNyAxLjIyM2MtMzUuNjk1IDc2LjQ5Mi0xMjguODk0IDIyNi41MTItMTI4Ljg5NCAyMjYuNTEycy0wLjExOS0wLjM1NC0wLjQ4Ni0wLjkzOGwtMjcuMjM1IDQ3LjQ4NWgxMzEuMjU0TDYxOS42MSAxMDIxLjcwNWw1Ni45MDMtMjI3LjEyOUg1NzMuMjM2bDM1Ljg4Ni0xNTAuMTljLTI5LjAzMyA3LjAxMS02My4zNSAxNi42NTQtMTAzLjk5MyAyOS43NCAwIDAtNTQuOTgyIDMyLjI0OS0xNTguMzgyLTYyLjAzNyAwIDAtNjkuNzM2LTYxLjUzMy0yOS4zMDQtNzYuOTA5IDE3LjE5Ni02LjUzOCA4My40OS0xNC44MzIgMTM1LjY0NS0yMS44OTQgNzAuNDg3LTkuNTQzIDExMy44NDgtMTQuNTk2IDExMy44NDgtMTQuNTk2cy0yMTcuMzE2IDMuMjU1LTI2OC44Ny00Ljg2NmMtNTEuNTU3LTguMTItMTE2Ljk1OS05NC4yNzUtMTMwLjg5LTE3MC4wMTkgMCAwLTIxLjU0Ny00MS41OCA0Ni4zMzQtMjEuODk0czM0OC44NTUgNzYuNjMyIDM0OC44NTUgNzYuNjMyLTM2NS40MjMtMTEyLjIwNC0zODkuNzQtMTM5LjU3OGMtMjQuMzEyLTI3LjM3NC03MS41NTctMTQ5LjQyMy02NS40MS0yMjQuNDIgMCAwIDIuNjY1LTE4LjY5OCAyMS44MDQtMTMuNjg3IDAgMCAyNzAuMTQ5IDEyMy42NCA0NTQuODc1IDE5MS4zMjMgMTg0LjcyNCA2Ny42ODMgMzQ1LjMzIDEwMi4xMDggMzI0LjU4IDE4OS43Mzl6IiBmaWxsPSIjMzI5NkZBIiBwLWlkPSI3MTM5Ij48L3BhdGg+PC9zdmc+Cg==&style=flat-square" /></a>
    <a href="https://demo.cloudrec.cloud"><img src="https://img.shields.io/badge/Demo-Try_CloudRec-orange?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB0PSIxNzQ3NzIxNjg1MDQxIiBjbGFzcz0iaWNvbiIgdmlld0JveD0iMCAwIDEwMjQgMTAyNCIgdmVyc2lvbj0iMS4xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHAtaWQ9IjkxMzAiIHdpZHRoPSIyMDAiIGhlaWdodD0iMjAwIj48cGF0aCBkPSJNMjkwLjA5OTIgNDA5LjZIMTU1LjEzNmEzNzEuNDA0OCAzNzEuNDA0OCAwIDAgMC0xNC4yODQ4IDEwMi40YzAgMzUuNTMyOCA0Ljk2NjQgNjkuODg4IDE0LjMzNiAxMDIuNGgxMzQuOTYzMmMtNS42MzItMzIuNzY4LTguNDk5Mi02Ni45MTg0LTguNDk5Mi0xMDIuNCAwLTM1LjQ4MTYgMi44NjcyLTY5LjYzMiA4LjQ5OTItMTAyLjR6IG01Mi4wNzA0IDBhNTQyLjEwNTYgNTQyLjEwNTYgMCAwIDAtOS4zNjk2IDEwMi40YzAgMzUuNzM3NiAzLjA3MiA2OS44ODggOS4zNjk2IDEwMi40SDQ4Ni40VjQwOS42SDM0Mi4xNjk2eiBtNzUuMDA4IDQ2MS4zNjMyQTQ5MS44Nzg0IDQ5MS44Nzg0IDAgMCAxIDMwMS41NjggNjY1LjZIMTczLjk3NzZhMzcyLjA3MDQgMzcyLjA3MDQgMCAwIDAgMjQzLjIgMjA1LjM2MzJ6IG02OS4yMjI0LTMuNTg0VjY2NS42SDM1NC45Njk2YzI0LjA2NCA3Ny4xMDcyIDY3Ljg0IDE0NC4yMzA0IDEzMS40MzA0IDIwMS44MzA0ek00MTcuMTc3NiAxNTMuMDg4QTM3Mi4wNzA0IDM3Mi4wNzA0IDAgMCAwIDE3My45Nzc2IDM1OC40SDMwMS41NjhhNDkxLjg3ODQgNDkxLjg3ODQgMCAwIDEgMTE1LjU1ODQtMjA1LjM2MzJ6IG02OS4yMjI0IDMuNTg0QzQyMi44MDk2IDIxNC4xMTg0IDM3OS4wODQ4IDI4MS4yNDE2IDM1NC45Njk2IDM1OC40SDQ4Ni40VjE1Ni41Njk2ek03MzMuOTAwOCA0MDkuNmM1LjYzMiAzMi43NjggOC40OTkyIDY2LjkxODQgOC40OTkyIDEwMi40IDAgMzUuNDgxNi0yLjg2NzIgNjkuNjMyLTguNDk5MiAxMDIuNGgxMzUuMDE0NGM5LjMxODQtMzIuNTEyIDE0LjI4NDgtNjYuODY3MiAxNC4yODQ4LTEwMi40cy00Ljk2NjQtNjkuODg4LTE0LjMzNi0xMDIuNGgtMTM0Ljk2MzJ6IG0tNTIuMDcwNCAwSDUzNy42djIwNC44aDE0NC4yMzA0YzYuMjQ2NC0zMi41MTIgOS4zNjk2LTY2LjY2MjQgOS4zNjk2LTEwMi40cy0zLjA3Mi02OS44ODgtOS4zNjk2LTEwMi40eiBtLTc1LjAwOCA0NjEuMzYzMkEzNzIuMDcwNCAzNzIuMDcwNCAwIDAgMCA4NTAuMDIyNCA2NjUuNkg3MjIuNDMyYTQ5MS44Nzg0IDQ5MS44Nzg0IDAgMCAxLTExNS41NTg0IDIwNS4zNjMyeiBtLTY5LjIyMjQtMy41ODRjNjMuNTkwNC01Ny41NDg4IDEwNy4zMTUyLTEyNC42NzIgMTMxLjQzMDQtMjAxLjc3OTJINTM3LjZ2MjAxLjgzMDR6TTYwNi44MjI0IDE1My4wODhBNDkxLjg3ODQgNDkxLjg3ODQgMCAwIDEgNzIyLjQzMiAzNTguNGgxMjcuNjQxNmEzNzIuMDcwNCAzNzIuMDcwNCAwIDAgMC0yNDMuMi0yMDUuMzYzMnogbS02OS4yMjI0IDMuNTg0VjM1OC40aDEzMS40MzA0Yy0yNC4wNjQtNzcuMTA3Mi02Ny44NC0xNDQuMjMwNC0xMzEuNDMwNC0yMDEuODMwNHpNNTEyIDk0Ny4yYTQzNS4yIDQzNS4yIDAgMSAxIDAtODcwLjQgNDM1LjIgNDM1LjIgMCAwIDEgMCA4NzAuNHoiIGZpbGw9IiM1MmE4ZjkiIHAtaWQ9IjkxMzEiPjwvcGF0aD48L3N2Zz4K" /></a>
    </a>
  </p>
</div>

CloudRec is an open source multi-cloud security posture management (CSPM) platform designed to help organizations improve the security of their cloud environments. CloudRec provides an open and scalable cloud assets collection framework and an OPA-based rule management engine. Based on CloudRec, you can easily implement comprehensive asset collection, real-time security inspection, and risk event operation in an enterprise cloud environment.

---

# Features

+ [🔗Rich inspection rules ](https://docs.cloudrec.cloud/Introductions/Detectionrules/)in addition to the built-in high-risk rules, it provides a flexible rule configuration engine based on OPA and supports multiple asset association analysis.
+ [🔗Multi-Cloud support ](https://docs.cloudrec.cloud/Introductions/Multi-Cloudsupport/): Built-in support for Alibaba Cloud, AWS, GCP and other cloud service providers, and can expand proprietary cloud on demand; It also provides Collector collection framework, which can be expanded and support other cloud vendors on demand.
+ User-friendly page: intuitive UI interface, convenient for users to carry out asset management, rule editing, risk operation, support multi-tenant

## 🌟 Modules

| Function Modules        | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| **Resource Discovery** | Covers mainstream public cloud platforms, automatically discovers 30+ cloud services and 200+ resource types, provides framework-level supports, and can be easily expanded on demand. |
| **Risk Detection**     | Based on enterprise-level real-world rules, covering multiple scenarios such as network protection, identity security, security protection, data protection, and log auditing. |
| **Policy Engine**      | Declarative policy management based on OPA, which can be dynamically adjust without hard coding, and no need to re-deploy |
| **Repair Closed Loop** | Integrated enterprise WeChat/DingTalk, alarm policy can be flexibly configured |


---

# 🚀 Quick Start
### Deploy Server
```
git clone https://github.com/antgroup/CloudRec.git

cd CloudRec

MYSQL_ROOT_PASSWORD=$(openssl rand -base64 16) docker-compose up -d
```
Access http://localhost:8080 after deployment.
### Deploy Collector
Login and get AccessToken for authentication of collector.
![accesstoken](doc/images/accesstoken.jpg)
```
docker exec -it cloudrec-cloud-rec-1 bash

nohup ./collectors --accessToken "${AccessToken}" > logs/task.log 2>&1 < /dev/null &
```

# 🏗 Architecture

![arch](doc/images/arch.jpg)

# 📚 Key Concepts

## 📡 Collector

```yaml
# Collector name, if not configured, hostname will be used
AgentName: "Alibaba CloudHuawei Cloud, AWS,Tencent Cloud,GCP,Baidu Cloud Collector"
# The server URL, http://localhost:8080 is used by default, and can be adjusted according to actual conditions
ServerUrl: "http://localhost:8080"

# eg：@every 30s、@every 5m、@every 1h
# @every 5m means obtaining an account every five minutes. If the current task is finished, skip this task.
Cron: "@every 5m"

# If RunOnlyOnce is set to false, the program will be executed once immediately, but the program will not exit. It will be run regularly according to the Cron cycle.
# If RunOnlyOnce is set to true, the program will be executed once immediately and then exit.
RunOnlyOnce: false

# Access token, which is used to authenticate the request. You can get it from the server
AccessToken: "change your access token"

#  Deployment site. If the deployment site is configured as 'S1', only cloudAccount of this site can be obtained. If the deployment site is not configured, all cloudAccount can be obtained.
#  eg:["S1"]
#  eg:["S1","I2","TE"]
Sites: [  ]

# Pay attention to the risk error information. If the error message contains text, the risk will be submitted to the server
AttentionErrorTexts: [ "NoPermission", "NotAuthorized", "NotApplicable",
                       "Forbidden.RAM", "Forbidden", "Throttling.User", "Throttling", "InvalidAccessKeyId.NotFound", "ServiceUnavailable", "Forbidden" ]
```



## 📜 Rego Policy Sample

```javascript
package ecs_security_groups_misconfig
import rego.v1

default risk := false
risk if {
  has_public_address
  count(security_groups_misconfig) != 0
}

public_ip_address := input.Instance.PublicIpAddress.IpAddress
has_public_address if {
  count(public_ip_address) > 0
}

security_groups_misconfig contains sg_rule if {
  sg_rule := input.SecurityGroups[_].Permissions[_]
  parts := split(sg_rule.SourceCidrIp, "/")
  size := to_number(parts[1])
  size <= 8
  sg_rule.Direction == "ingress"
  sg_rule.Policy == "Accept"
}
```

# 🤝 How to contribute

To check detailed guidelines for new contributions, please refer (https://docs.cloudrec.cloud/ContributionGuide/ContributionStep.html)

## Contributors Wall
<a href="https://github.com/antgroup/CloudRec/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=antgroup/CloudRec&max=200" />
</a>

# **<font style="color:rgb(38, 38, 38);">📬</font>** Community

[https://discord.gg/WpWT9Q8BkD](https://discord.gg/WpWT9Q8BkD)

# 📜 LICENSE

This project uses the Apache-2.0 LICENSE, the full text of which is available in the LICENSE document. Commercial use is subject to supplementary terms.

