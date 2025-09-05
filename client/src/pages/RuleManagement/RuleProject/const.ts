/**
 * The Rego PlayGround
 * Default Template
 * */
export const DEFAULT_CODE_EDITOR = `package example

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false

# When a user requests a private resource using GET, it is considered a risk.

risk if {
    input.method == "GET"
    input.path == "/private/resource"
}

# When an admin uses GET to request access, it is considered a risk.

risk if {
    input.method == "GET"
    input.path == "/admin/resource"
    input.user.role == "admin"
}

### For more details please see: https://www.openpolicyagent.org/docs/latest/#example`;

export const CONTEXT_TEMPLATE = `实例：{$.ResourceId} ，名称：{$.ResourceName} 存在风险。`;
