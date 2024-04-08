module github.com/openbao/go-kms-wrapping/wrappers/gcpckms/v2

go 1.22.1

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	cloud.google.com/go/kms v1.10.1
	github.com/openbao/go-kms-wrapping/v2 v2.0.0-00010101000000-000000000000
	golang.org/x/net v0.17.0
	google.golang.org/api v0.114.0
)

require (
	cloud.google.com/go/compute v1.19.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.13.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.3 // indirect
	github.com/googleapis/gax-go/v2 v2.7.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/oauth2 v0.7.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/grpc v1.56.3 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

retract [v2.0.0, v2.0.10]
