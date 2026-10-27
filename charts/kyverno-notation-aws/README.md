# kyverno-notation-aws

![Version: v1.1](https://img.shields.io/badge/Version-v1.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v1.1](https://img.shields.io/badge/AppVersion-v1.1-informational?style=flat-square)

Kyverno extension service for Notation and the AWS signer

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| region | string | `"us-west-2"` |  |
| nameOverride | string | `nil` | Override the name of the chart |
| fullnameOverride | string | `nil` | Override the expanded name of the chart |
| namespaceOverride | string | `nil` | Override the namespace the chart deploys to |
| image.defaultRegistry | string | `"ghcr.io"` | Image registry |
| image.registry | string | `nil` |  |
| image.repository | string | `"nirmata/kyverno-notation-aws"` | Image repository |
| image.tag | string | `nil` | Image tag Defaults to appVersion in Chart.yaml if omitted |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| crds.install | bool | `true` | Whether to have Helm install the Kyverno Notation AWS CRDs. |
| deployment.updateStrategy | object | See [values.yaml](values.yaml) | Deployment update strategy. Ref: https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy |
| deployment.imagePullSecrets | object | `{}` | Image pull secrets in case IRSA isn't configured, this will define the `--imagePullSecrets` argument |
| deployment.allowInsecureRegistry | bool | `false` | Allow insecure registry specifies whether to allow insecure connections to registries. Not recommended. |
| deployment.maxSignatureAttempts | int | `30` | Max signature attempts specifies the maximum number of signature envelopes that will be processed for verification |
| deployment.tokenAudiences | list | `[]` | TokenReview audiences accepted from callers. Empty preserves the API server audience. Changing this requires coordinating caller token audiences. |
| serviceAccount.enabled | bool | `true` |  |
| serviceAccount.name | string | `nil` | The ServiceAccount name |
| serviceAccount.annotations | object | `{}` | Annotations for the ServiceAccount |
| configMap.name | string | `"notation-plugin-config"` | The notation-plugin-config configmap name |
| nodeSelector | object | `{}` |  |
| tolerations | list | `[]` |  |
| affinity | object | `{}` |  |
| customLabels | object | `{}` | user supplied labels to apply to all resources excluding label selectors |
| startupProbe | object | See [values.yaml](values.yaml) | Startup probe. The block is directly forwarded into the deployment, so you can use whatever startupProbes configuration you want. ref: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/ |
| livenessProbe | object | See [values.yaml](values.yaml) | Liveness probe. The block is directly forwarded into the deployment, so you can use whatever livenessProbe configuration you want. ref: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/ |
| readinessProbe | object | See [values.yaml](values.yaml) | Readiness Probe. The block is directly forwarded into the deployment, so you can use whatever readinessProbe configuration you want. ref: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/ |
| test.sleep | int | `20` | Sleep time before running test |

## Caller token audience migration

For Kyverno callers using a projected token with audience
`kyverno-svc.kyverno.io`, use:

```yaml
deployment:
  tokenAudiences:
    - kyverno-svc.kyverno.io
```

This renders `--tokenAudiences=kyverno-svc.kyverno.io`. An empty or omitted list
does not render the argument and keeps the previous API-server-audience check.
Entries must be nonempty strings without commas or whitespace. Multiple entries
are accepted alternatives, not requirements that every audience be present.
The allowed-caller identity check still applies, and token review stays enabled.

First stage an image containing the audience support with the list omitted.
Then coordinate the caller token change and audience configuration; old
API-server-only tokens fail after the explicit scoped audience is enabled,
and scoped-only tokens fail before it is enabled. Rollback must coordinate
both sides. Do not disable authentication or add an API-server fallback.

This value requires a separately published compatible extension image and chart.
Do not pass it to the old `v1.1` image, which does not support the flag. Existing
chart/app versions are not release identifiers for this unpublished change.
Keep the current TLS CA, IRSA annotations, RBAC, and trust resources unchanged.
See the root [compatibility test notes](../../README.md#local-compatibility-tests)
for local validation and the remaining AWS/Kubernetes rollout checks.
| test.image.registry | string | `nil` | Image registry |
| test.image.repository | string | `"busybox"` | Image repository |
| test.image.tag | string | `"1.35"` | Image tag Defaults to `latest` if omitted |
| test.image.pullPolicy | string | `nil` | Image pull policy Defaults to image.pullPolicy if omitted |
| test.resources.limits | object | `{"cpu":"100m","memory":"256Mi"}` | Pod resource limits |
| test.resources.requests | object | `{"cpu":"10m","memory":"64Mi"}` | Pod resource requests |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.11.0](https://github.com/norwoodj/helm-docs/releases/v1.11.0)
