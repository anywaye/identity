package client


var _ = struct{}{}

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 --config oapi-codegen.yaml -generate models,client ../openapi/v1.yaml
