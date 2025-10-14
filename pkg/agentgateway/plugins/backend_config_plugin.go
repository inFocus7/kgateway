package plugins

import (
	"fmt"
	"os"

	"github.com/agentgateway/agentgateway/go/api"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/wellknown"
	"github.com/kgateway-dev/kgateway/v2/pkg/agentgateway/utils"
	"github.com/kgateway-dev/kgateway/v2/pkg/utils/kubeutils"
)

// NewBackendConfigPlugin creates a new BackendConfigPolicy plugin
func NewBackendConfigPlugin(agw *AgwCollections) AgwPlugin {
	clusterDomain := kubeutils.GetClusterDomainName()
	policyCol := krt.NewManyCollection(agw.BackendConfigPolicies, func(krtctx krt.HandlerContext, bcfg *v1alpha1.BackendConfigPolicy) []AgwPolicy {
		return translatePoliciesForBackendConfig(krtctx, agw.Backends, agw.Secrets, bcfg, clusterDomain)
	})
	return AgwPlugin{
		ContributesPolicies: map[schema.GroupKind]PolicyPlugin{
			wellknown.BackendConfigPolicyGVK.GroupKind(): {
				Policies: policyCol,
			},
		},
		ExtraHasSynced: func() bool {
			return policyCol.HasSynced()
		},
	}
}

// translatePoliciesForService generates backend ConfigPolicy policies
func translatePoliciesForBackendConfig(
	krtctx krt.HandlerContext,
	backends krt.Collection[*v1alpha1.Backend],
	secrets krt.Collection[*corev1.Secret],
	bcfg *v1alpha1.BackendConfigPolicy,
	clusterDomain string,
) []AgwPolicy {
	logger := logger.With("plugin_kind", "backendconfig")
	var policies []AgwPolicy

	for _, target := range bcfg.Spec.TargetRefs {
		var policyTarget *api.PolicyTarget

		switch string(target.Kind) {
		case wellknown.BackendGVK.Kind:
			backendRef := types.NamespacedName{
				Name:      string(target.Name),
				Namespace: bcfg.Namespace,
			}
			backend := krt.FetchOne(krtctx, backends, krt.FilterObjectName(backendRef))
			if backend == nil || *backend == nil {
				logger.Error("backend not found; skipping policy", "backend", backendRef, "policy", kubeutils.NamespacedNameFrom(bcfg))
				continue
			}
			spec := (*backend).Spec
			if spec.AI != nil {
				switch {
				// Single provider backend
				case spec.AI.LLM != nil:
					if target.SectionName != nil {
						logger.Error("sectionName must be omitted when targeting AI backend with single provider; skipping policy", "backend", backendRef, "policy", kubeutils.NamespacedNameFrom(bcfg))
						continue
					}
					// Single provider backends also use api.ProviderGroups(ref: buildAIIr), so policies must be applied per-provider using PolicyTarget_SubBackend
					policyTarget = &api.PolicyTarget{
						Kind: &api.PolicyTarget_SubBackend{
							SubBackend: utils.InternalBackendName(backendRef.Namespace, string(backendRef.Name), utils.SingularLLMProviderSubBackendName),
						},
					}
				// Multi-provider backend
				case len(spec.AI.PriorityGroups) > 0:
					if target.SectionName != nil {
						// target SubBackend
						policyTarget = &api.PolicyTarget{
							Kind: &api.PolicyTarget_SubBackend{
								SubBackend: utils.InternalBackendName(backendRef.Namespace, string(backendRef.Name), string(*target.SectionName)),
							},
						}
					} else {
						// target entire backend
						policyTarget = &api.PolicyTarget{
							Kind: &api.PolicyTarget_Backend{
								Backend: utils.InternalBackendName(bcfg.Namespace, string(target.Name), ""),
							},
						}
					}
				default:
					logger.Warn("unknown backend type", "backend", backendRef, "policy", kubeutils.NamespacedNameFrom(bcfg))
					continue
				}
			} else {
				// The target defaults to <backend-namespace>/<backend-name>.
				// If SectionName is specified to select a specific target in the Backend,
				// the target becomes <backend-namespace>/<backend-name>/<section-name>
				policyTarget = &api.PolicyTarget{
					Kind: &api.PolicyTarget_Backend{
						Backend: utils.InternalBackendName(bcfg.Namespace, string(target.Name), string(ptr.OrEmpty(target.SectionName))),
					},
				}
			}
		case wellknown.ServiceKind:
			hostname := fmt.Sprintf("%s.%s.svc.%s", target.Name, bcfg.Namespace, clusterDomain)
			// If SectionName is specified to select the port, use service/<namespace>/<hostname>:<port>
			if port := ptr.OrEmpty(target.SectionName); port != "" {
				policyTarget = &api.PolicyTarget{
					Kind: &api.PolicyTarget_Backend{
						Backend: fmt.Sprintf("service/%s/%s:%s", bcfg.Namespace, hostname, port),
					},
				}
			} else {
				// Select the entire service with <namespace>/<hostname>
				policyTarget = &api.PolicyTarget{
					Kind: &api.PolicyTarget_Service{
						Service: fmt.Sprintf("%s/%s", bcfg.Namespace, hostname),
					},
				}
			}

		default:
			logger.Warn("unsupported target kind", "kind", target.Kind, "policy", bcfg.Name)
			continue
		}
		// Handle TLS configuration for client certificate attachment
		var cert, key *wrapperspb.BytesValue

		if bcfg.Spec.TLS != nil {
			// Handle client certificates and keys
			if bcfg.Spec.TLS.SecretRef != nil {
				secret := krt.FetchOne(krtctx, secrets, krt.FilterObjectName(types.NamespacedName{
					Name:      bcfg.Spec.TLS.SecretRef.Name,
					Namespace: bcfg.Namespace,
				}))
				if secret != nil && *secret != nil {
					// Extract certificate chain
					if certData, ok := (*secret).Data[corev1.TLSCertKey]; ok {
						cert = wrapperspb.Bytes(certData)
					}

					// Extract private key
					if privateKeyData, ok := (*secret).Data[corev1.TLSPrivateKeyKey]; ok {
						key = wrapperspb.Bytes(privateKeyData)
					}
				} else {
					logger.Error("TLS secret not found", "secret", bcfg.Spec.TLS.SecretRef.Name, "policy", kubeutils.NamespacedNameFrom(bcfg))
					return nil
				}
			}

			// Handle TLS files (for file-based TLS configuration)
			if bcfg.Spec.TLS.Files != nil {
				// For file-based TLS, we need to read the files from the filesystem
				// This assumes the files are mounted/available in the proxy's filesystem
				if bcfg.Spec.TLS.Files.TLSCertificate != nil && *bcfg.Spec.TLS.Files.TLSCertificate != "" {
					certData, err := os.ReadFile(*bcfg.Spec.TLS.Files.TLSCertificate)
					if err != nil {
						logger.Error("error reading TLS certificate file", "file", *bcfg.Spec.TLS.Files.TLSCertificate, "policy", kubeutils.NamespacedNameFrom(bcfg), "error", err)
						return nil
					}
					cert = wrapperspb.Bytes(certData)
				}

				if bcfg.Spec.TLS.Files.TLSKey != nil && *bcfg.Spec.TLS.Files.TLSKey != "" {
					keyData, err := os.ReadFile(*bcfg.Spec.TLS.Files.TLSKey)
					if err != nil {
						logger.Error("error reading TLS key file", "file", *bcfg.Spec.TLS.Files.TLSKey, "policy", kubeutils.NamespacedNameFrom(bcfg), "error", err)
						return nil
					}
					key = wrapperspb.Bytes(keyData)
				}
			}
		}

		policy := &api.Policy{
			Name:   bcfg.Namespace + "/" + bcfg.Name + ":backendconfig" + attachmentName(policyTarget),
			Target: policyTarget,
			Spec: &api.PolicySpec{Kind: &api.PolicySpec_BackendTls{
				BackendTls: &api.PolicySpec_BackendTLS{
					Cert:     cert,
					Key:      key,
					Hostname: wrapperspb.String(string(ptr.OrEmpty(bcfg.Spec.TLS.Sni))),
				},
			}},
		}
		policies = append(policies, AgwPolicy{policy})
	}

	return policies
}
