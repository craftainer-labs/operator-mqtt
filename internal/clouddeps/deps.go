//go:build tools

// Package clouddeps pins the cloud SDK modules in go.mod before the cloud
// backends (NKmqtt-1, NKmqtt-2) import them: `go mod tidy` drops a
// requirement nothing imports, and the dependency-only change NKmqtt-0 must
// keep them and their go.sum entries. The tools build tag keeps this file out
// of every build and test; tidy still reads it. The AWS IoT client is imported
// by internal/iotcore and so is no longer pinned here; delete this package
// once the backends import the rest.
package clouddeps

import (
	_ "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	_ "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid/v2"
	_ "github.com/aws/aws-sdk-go-v2/config"
)
