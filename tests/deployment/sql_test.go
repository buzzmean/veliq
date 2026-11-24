package deployment

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Execute the actual generator output against PostgreSQL, then authenticate with
// the exact original password. Fixtures never log credentials or generated SQL.
func TestGeneratedSQLAuthenticatesExactPassword(t *testing.T) {
	url := os.Getenv("VELIQ_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("requires PostgreSQL integration database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	for i, password := range []string{"quote'password", `back\slash'\`, "'; DROP ROLE postgres; --", "space\r\nline", "пароль"} {
		name := fmt.Sprintf("sql_regression_%d_%d", time.Now().UnixNano(), i)
		path := filepath.Join(t.TempDir(), "password")
		if err := os.WriteFile(path, []byte(password), 0600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.CommandContext(ctx, "python3", "../../deploy/vps/database-sql.py", path).Output()
		if err != nil {
			t.Fatal("generator failed")
		}
		sql := strings.ReplaceAll(string(output), "neexitlag", name)
		// Match psql -f: each statement is committed separately (CREATE DATABASE
		// cannot run inside a multi-statement implicit transaction).
		boundary := strings.LastIndex(sql, "CREATE DATABASE ")
		first := strings.Index(sql, "\n") + 1
		for _, statement := range []string{sql[:first], sql[first:boundary], sql[boundary:]} {
			_, err = admin.Exec(ctx, statement)
			if err != nil {
				t.Fatal("generated SQL failed (SQL/password suppressed)")
			}
		}
		cfg, err := pgx.ParseConfig(url)
		if err != nil {
			t.Fatal(err)
		}
		cfg.User = name
		cfg.Password = password
		cfg.Database = name
		login, err := pgx.ConnectConfig(ctx, cfg)
		if err == nil {
			err = login.Ping(ctx)
			login.Close(ctx)
		}
		_, dropDB := admin.Exec(ctx, "DROP DATABASE "+name)
		_, dropRole := admin.Exec(ctx, "DROP ROLE "+name)
		if err != nil {
			t.Fatal("exact password authentication failed")
		}
		if dropDB != nil || dropRole != nil {
			t.Fatal("fixture cleanup failed")
		}
	}
}
