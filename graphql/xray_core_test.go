// SPDX-License-Identifier: AGPL-3.0-only
package graphql

import (
	"context"
	"testing"
)

func TestXrayCoreSchema(t *testing.T) {
	schema, err := Schema()
	if err != nil {
		t.Fatal(err)
	}
	// The core manager can execute binaries: no unauthenticated access, including
	// the release-list query and the rollback mutation.
	for _, query := range []string{
		`{ geodataStatus { daily running updateTime error files { name path updated } } }`,
		`mutation { updateGeodata }`,
		`mutation { setGeodataDaily(enabled:true, at:"05:30") }`,
		`{ xrayCore { mode path version error canRollback } }`,
		`{ xrayTask { id status phase downloadedBytes totalBytes error } }`,
		`mutation { startXrayTask(kind:"install", version:"v26.10.31", path:"") { id status } }`,
		`{ xrayReleases { version prerelease } }`,
		`mutation { selectXrayCore(mode:"system", path:"/not/executed") { mode } }`,
		`mutation { installXrayCore(version:"v26.10.31") { mode } }`,
		`mutation { rollbackXrayCore { mode } }`,
	} {
		response := schema.Exec(context.Background(), query, "", nil)
		if len(response.Errors) == 0 {
			t.Fatalf("unprotected core operation: %s", query)
		}
	}
	ctx := context.WithValue(context.Background(), "role", "ADMIN")
	response := schema.Exec(ctx, `{ xrayCore { mode path version error canRollback } }`, "", nil)
	if len(response.Errors) > 0 {
		t.Fatal(response.Errors)
	}
	response = schema.Exec(ctx, `{ geodataStatus { daily running updateTime error files { name path updated } } }`, "", nil)
	if len(response.Errors) > 0 {
		t.Fatal(response.Errors)
	}
	response = schema.Exec(ctx, `{ xrayTask { id status kind version phase downloadedBytes totalBytes error } }`, "", nil)
	if len(response.Errors) > 0 {
		t.Fatal(response.Errors)
	}
}
