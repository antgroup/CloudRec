# Changelog

## [0.2] - 2025-08-12
- Improve the timeliness of asset collection in the case of multiple accounts
- Collection of abnormal logs and manual cloud account-triggered collection tasks
- Optimized frontend interaction and display for better user experience
- Other bug fixes

## [0.1] - 2025-05-01
- Project initialization, foundational features launched, establishing the platform architecture.
- Cloud Account Management: Supports creation and query of cloud accounts, enabling unified management in multi-cloud environments, enhancing account security and traceability.
- Asset Management: Automatically integrates with collector to gather cloud assets, supports both full and incremental asset synchronization, aiding asset visualization and compliance inventory.
- Rule Management:
  - Supports creation, query, and update of rules, flexibly adapting to various security and compliance scenarios.
  - Rule Grouping: Allows grouping of rules for batch configuration and layered policy management.
  - Whitelist Management: Provides global whitelist configuration, supports creation and deletion of whitelists, flexibly handling special business exemption needs.
- Risk Management:
  - Supports risk status query and handling, automatically associates assets and rules, improving risk response efficiency.
  - Risk handling process is traceable, supporting multi-dimensional statistics and analysis.
- Operations Management:
  - User Management: Supports multi-user system, fine-grained permission allocation, ensuring platform security.
  - Tenant Management: Multi-tenant isolation, meeting enterprise-level multi-organization management needs.
  - Collector Management: Supports registration, monitoring, and maintenance of collector nodes, ensuring stable data collection.
  - Subscription Management: Supports subscription and push of events such as risks and assets, improving information delivery timeliness.
  - Variable Management: Centralized management of platform variables, facilitating flexible configuration of rules and processes.