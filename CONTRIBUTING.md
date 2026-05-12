# Contribution
First of all, thank you for considering contributing to this project. It's people like you that make it a reality for the community. There are many ways to contribute, and we appreciate all of them.

This guide will help you get started with contributing to this project.

## Fork The Repository
1. Fork the repository you want to contribute to by clicking the "Fork" button on the project page.
2. Clone the repository to your local machine using the following command:
`git clone https://github.com/<YOUR-GITHUB-USERNAME>/CloudRec`
   Please replace <YOUR-GITHUB-USERNAME> with your GitHub username.

## Create A New Development Environment
For secondary development, please read：👉[Development Guide](https://cloudrec.yuque.com/org-wiki-cloudrec-iew3sz/hocvhx/fnczqhvg07as1gaf)

## New Branch And Make Changes
1. Create a new branch for your changes using the following command: `git checkout -b <branch-name>`
   Please replace <branch-name> with a descriptive name for your branch.
2. Make your changes to the code or documentation. 
3. Add tests for your changes if necessary.
7. Add and commit your changes using the following commands: `git add xxxx`

   make sure to replace xxxx with the files you want to commit.
then commit your changes using the following command:`git commit -m "your commit message"`

9. Push the changes to your forked repository using the following command: `git push origin <branch-name>`

## Create A Pull Request
Go to the GitHub website and navigate to your forked repository.

Click the "New pull request" button.

Select the branch you just pushed to and the branch you want to merge into on the original repository. Write necessary information about your changes and click "Create pull request".

Wait for the project maintainer to review your changes and provide feedback.

That's it you made it

## CloudRec Lite Contributions

CloudRec Lite is the single-binary local CSPM path under `lite/`. It has a few
extra quality gates because rule and collector changes can affect user trust.

Before opening a Lite pull request, run from `lite/`:

```sh
go test -p 1 ./...
node --check internal/server/web/app.js
go run ./cmd/cloudrec-lite rules audit --rules ./rules/alicloud --provider alicloud --review-ledger ./rules/alicloud/review-ledger.json --format json
go run ./cmd/cloudrec-lite rules coverage --rules ./rules/alicloud --provider alicloud --samples ./samples/alicloud --review-ledger ./rules/alicloud/review-ledger.json --format json
go run ./cmd/cloudrec-lite rules validate --rules ./rules/alicloud --provider alicloud --samples ./samples/alicloud --format json
```

For Alibaba Cloud rule changes:

1. Do not change Rego logic casually.
2. Record the current behavior, official documentation basis, field
   dependencies, false-positive or false-negative impact, and fixture coverage in
   `lite/rules/alicloud/review-ledger.json`.
3. Add or update sanitized fixtures. Do not include real account IDs, AK/SK,
   public IPs that belong to users, bucket names, project names, or other
   sensitive resource identifiers.
4. Ensure every active rule has remediation text. If a rule has no product-safe
   repair guidance, mark the source clearly in the review ledger.

For collector or adapter changes:

1. Prefer normalizing collector output to match existing rule input contracts
   before changing rules.
2. Preserve partial-failure behavior so one unsupported, throttled, or
   permission-denied product does not fail the whole scan.
3. Never print credentials or raw secret-bearing evidence in logs, CLI output,
   Web UI, or exported reports.

## Contact Us
If you have any questions, please feel free to contact us, we are very willing to provide you with necessary help!
