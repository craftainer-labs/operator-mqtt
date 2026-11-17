//go:build tools

// Package clouddeps pins a cloud SDK module in go.mod that no package imports
// yet: `go mod tidy` drops a requirement nothing imports. The tools build tag
// keeps this file out of every build and test; tidy still reads it. The AWS IoT
// client (internal/iotcore), azidentity and armeventgrid (internal/eventgrid)
// are imported by the operator and so are no longer pinned here; delete this
// package once something imports the AWS SDK config module.
package clouddeps

import (
	_ "github.com/aws/aws-sdk-go-v2/config"
)
