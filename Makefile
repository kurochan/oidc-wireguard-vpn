build: lint
	GOOS=linux go build

lint:
	GOOS=linux golangci-lint run --fix --enable=golint,gosec,prealloc,gocognit,bodyclose,gofmt,goimports 

clean:
	rm -f ./oidc-wireguard-vpn

