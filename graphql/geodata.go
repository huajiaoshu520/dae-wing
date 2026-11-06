// SPDX-License-Identifier: AGPL-3.0-only
package graphql

import "github.com/daeuniverse/dae-wing/component/geodata"

func (*queryResolver) GeodataStatus() *geodata.Status { return geodata.Default.Status() }

func (*MutationResolver) UpdateGeodata() (bool, error) {
	err := geodata.Default.Start()
	return err == nil, err
}

func (*MutationResolver) SetGeodataDaily(args struct{ Enabled bool }) (bool, error) {
	err := geodata.Default.SetDaily(args.Enabled)
	return err == nil, err
}
