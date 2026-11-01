// SPDX-License-Identifier: AGPL-3.0-only
package graphql

import (
	"context"

	"github.com/daeuniverse/dae-wing/component/xraycore"
)

func (*queryResolver) XrayTask() *xraycore.Task { return xraycore.Default.Task() }

func (*MutationResolver) StartXrayTask(args struct{ Kind, Version, Path string }) (*xraycore.Task, error) {
	return xraycore.Default.StartTask(args.Kind, args.Version, args.Path)
}

func (*queryResolver) XrayCore(ctx context.Context) *xraycore.Status {
	return xraycore.Default.Status(ctx)
}

func (*queryResolver) XrayReleases(ctx context.Context) ([]*xraycore.Release, error) {
	return xraycore.Default.Releases(ctx)
}

func (*MutationResolver) SelectXrayCore(ctx context.Context, args struct{ Mode, Path string }) (*xraycore.Status, error) {
	return xraycore.Default.Select(ctx, args.Mode, args.Path)
}

func (*MutationResolver) InstallXrayCore(ctx context.Context, args struct{ Version string }) (*xraycore.Status, error) {
	return xraycore.Default.Install(ctx, args.Version)
}

func (*MutationResolver) RollbackXrayCore(ctx context.Context) (*xraycore.Status, error) {
	return xraycore.Default.Rollback(ctx)
}
