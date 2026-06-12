package main

import (
	"testing"
)

func TestCLIValidate(t *testing.T) {
	ptr := func(i int) *int { return &i }

	tests := []struct {
		name    string
		cli     CLI
		wantErr bool
	}{
		{
			name:    "no flags",
			cli:     CLI{},
			wantErr: false,
		},
		{
			name:    "valid verify",
			cli:     CLI{Verify: ptr(12345)},
			wantErr: false,
		},
		{
			name:    "zero app id",
			cli:     CLI{Verify: ptr(0)},
			wantErr: true,
		},
		{
			name:    "negative app id",
			cli:     CLI{Verify: ptr(-1)},
			wantErr: true,
		},
		{
			name:    "dry-run alone",
			cli:     CLI{DryRun: true},
			wantErr: false,
		},
		{
			name:    "dry-run with delete",
			cli:     CLI{DryRun: true, Delete: true},
			wantErr: true,
		},
		{
			name:    "dry-run with verify",
			cli:     CLI{DryRun: true, Verify: ptr(1)},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cli.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
