package migrations

import "embed"

//go:embed *.sql
var FS embed.FS

func InitSQL() (string, error) {
	b, err := FS.ReadFile("001_init.sql")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
