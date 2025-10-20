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

// translatePoliciesForBackendConfig generates backend ConfigPolicy policies
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
				policyTarget = &api.PolicyTarget{
					Kind: &api.PolicyTarget_Backend{
						Backend: utils.InternalBackendName(bcfg.Namespace, string(target.Name), string(ptr.OrEmpty(target.SectionName))),
					},
				}
			}
		case wellknown.ServiceKind:
			hostname := fmt.Sprintf("%s.%s.svc.%s", target.Name, bcfg.Namespace, clusterDomain)
			if port := ptr.OrEmpty(target.SectionName); port != "" {
				policyTarget = &api.PolicyTarget{
					Kind: &api.PolicyTarget_Backend{
						Backend: fmt.Sprintf("service/%s/%s:%s", bcfg.Namespace, hostname, port),
					},
				}
			} else {
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

		tls, err := getConfigPolicyTLS(krtctx, secrets, bcfg)
		if err != nil {
			logger.Error("error getting config policy TLS", "policy", kubeutils.NamespacedNameFrom(bcfg), "error", err)
			continue
		}

		policy := &api.Policy{
			Name:   bcfg.Namespace + "/" + bcfg.Name + ":backendconfig" + attachmentName(policyTarget),
			Target: policyTarget,
			Spec: &api.PolicySpec{Kind: &api.PolicySpec_BackendTls{
				BackendTls: tls,
			}},
		}
		policies = append(policies, AgwPolicy{policy})
	}

	return policies
}

func getConfigPolicyTLS(krtctx krt.HandlerContext, secrets krt.Collection[*corev1.Secret], bcfg *v1alpha1.BackendConfigPolicy) (*api.PolicySpec_BackendTLS, error) {
	var cert, key *wrapperspb.BytesValue

	var hostname *wrapperspb.StringValue = nil
	if bcfg.Spec.TLS != nil {
		hostname = wrapperspb.String(string(ptr.OrEmpty(bcfg.Spec.TLS.Sni)))

		// Handle client certificates and keys
		if bcfg.Spec.TLS.SecretRef != nil {
			secret := krt.FetchOne(krtctx, secrets, krt.FilterObjectName(types.NamespacedName{
				Name:      bcfg.Spec.TLS.SecretRef.Name,
				Namespace: bcfg.Namespace,
			}))
			if secret != nil && *secret != nil {
				if certData, ok := (*secret).Data[corev1.TLSCertKey]; ok {
					cert = wrapperspb.Bytes(certData)
				}

				if privateKeyData, ok := (*secret).Data[corev1.TLSPrivateKeyKey]; ok {
					key = wrapperspb.Bytes(privateKeyData)
				}
			} else {
				return nil, fmt.Errorf("TLS secret not found: %s", bcfg.Spec.TLS.SecretRef.Name)
			}
		}

		// Handle TLS files
		if bcfg.Spec.TLS.Files != nil {
			// For file-based TLS, we need to read the files from the filesystem
			if bcfg.Spec.TLS.Files.TLSCertificate != nil && *bcfg.Spec.TLS.Files.TLSCertificate != "" {
				certData, err := os.ReadFile(*bcfg.Spec.TLS.Files.TLSCertificate)
				if err != nil {
					return nil, fmt.Errorf("error reading TLS certificate file %s: %w", *bcfg.Spec.TLS.Files.TLSCertificate, err)
				}
				cert = wrapperspb.Bytes(certData)
			}

			if bcfg.Spec.TLS.Files.TLSKey != nil && *bcfg.Spec.TLS.Files.TLSKey != "" {
				keyData, err := os.ReadFile(*bcfg.Spec.TLS.Files.TLSKey)
				if err != nil {
					return nil, fmt.Errorf("error reading TLS key file %s: %w", *bcfg.Spec.TLS.Files.TLSKey, err)
				}
				key = wrapperspb.Bytes(keyData)
			}
		}
	}

	return &api.PolicySpec_BackendTLS{
		Cert:     cert,
		Key:      key,
		Hostname: hostname,
		// No mTLS support yet
		Insecure: wrapperspb.Bool(true),
	}, nil
}
