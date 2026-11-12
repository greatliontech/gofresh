module github.com/greatliontech/gofresh

go 1.27.0

require (
	github.com/greatliontech/go-x-tools v0.52.1-0.20261112192041-23335f31d87c
	github.com/greatliontech/stipulator/stipulate/structural v0.3.1
	golang.org/x/mod v0.42.0
	golang.org/x/sys v0.49.0
)

require golang.org/x/sync v0.24.0 // indirect

retract v0.119.0 // Poisoned in proxy.golang.org by a deleted tag.
