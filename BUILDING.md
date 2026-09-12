# Building sealedsecrets

The project requires Go 1.27.0 or newer and selects Go 1.27.1 through the
`toolchain` directive in `go.mod`. Go downloads that toolchain automatically when
needed unless automatic toolchain selection has been disabled.

```sh
go mod download
go build -mod=readonly .
go test -mod=readonly ./...
go vet -mod=readonly ./...
go mod verify
```

Dependencies are pinned in `go.mod` and verified with `go.sum`. There is no
`vendor` directory: the previous vendored files contained no local patches, and
the repository history recorded no offline-build requirement. An uncached build
needs access to the Go module proxy; subsequent builds can use the module cache.
GoReleaser downloads the pinned modules and builds with `-mod=readonly`.

## Updating dependencies

Keep `k8s.io/api`, `k8s.io/apimachinery`, and `k8s.io/client-go` on the same
release. Keep `k8s.io/kube-openapi` on the revision selected by that Kubernetes
release until its compatibility is checked: newer OpenAPI revisions currently
use `structured-merge-diff/v7`, while Kubernetes 0.37 uses v6.

After an update, run `go mod tidy` and the checks above. The seal/unseal tests use
generated keys and mocked API responses; they do not need a Kubernetes cluster.

The Sealed Secrets library now uses the `github.com/bitnami/sealed-secrets`
module path. Version 0.40 supports null `spec.template.data` values to omit
encrypted keys from the rendered Secret, and encrypted values take precedence
over non-null template entries with the same name. Unsealing follows those
upstream rendering rules.

## Controller discovery

Without controller flags, the CLI first tries `kube-system` and the
`sealed-secrets-controller` Service. If those defaults are absent or access is
denied, it discovers active sealing-key namespaces for unsealing and controller
Services for sealing. Key discovery requests metadata across namespaces, then
fetches key contents only from the selected namespace. Certificate discovery
uses Services and does not require Secret access. Metrics Services are excluded.

Discovery requires permission to list the relevant resource across namespaces.
Multiple matching namespaces or Services require an explicit choice; the CLI
does not combine keys from different namespaces. Explicit controller flags
constrain discovery, including flags supplied through configuration.

For example, a Helm installation may need:

```sh
sealedsecrets unseal secrets.yaml --controller-namespace sealed-secrets
sealedsecrets seal secrets.yaml --force --controller-namespace sealed-secrets --controller-name sealed-secrets
```

`--namespace` selects the Secret's namespace, while `--controller-namespace`
selects where the sealing controller and its keys are installed.
