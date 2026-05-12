package log

import (
	"fmt"
	"strings"
	"testing"
)

func TestRedactLogText(t *testing.T) {
	accessKeyID := "LT" + "AI5abcdef123456"
	standaloneAccessKeyID := "LT" + "AI5standalone1234567890"
	input := fmt.Sprintf(`Post "https://ecs.aliyuncs.com/?AccessKeyId=%s&Signature=abcdef&SecurityToken=token" {"AccessKeySecret":"secret"} standalone=%s`, accessKeyID, standaloneAccessKeyID)
	output := redactLogText(input)

	for _, leak := range []string{accessKeyID, standaloneAccessKeyID, "Signature=abcdef", "SecurityToken=token", `"AccessKeySecret":"secret"`} {
		if strings.Contains(output, leak) {
			t.Fatalf("redacted output still contains %q: %s", leak, output)
		}
	}
}
