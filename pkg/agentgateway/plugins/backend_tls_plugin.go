package plugins

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/agentgateway/agentgateway/go/api"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/translator/sslutils"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/wellknown"
	"github.com/kgateway-dev/kgateway/v2/pkg/agentgateway/utils"
	"github.com/kgateway-dev/kgateway/v2/pkg/utils/kubeutils"
)

// TODO: Should we disallow/error when more than one backend policy is set for a backend?
// Agentgateway does an `or` in this case, so it may make sense to disallow here and simplify the logic a bit.

// NewBackendTLSPlugin creates a new BackendTLSPolicy plugin
// It merges the BackendTLSPolicy and BackendConfigPolicy plugins into a single AgentGateway plugin on a per-target basis.
func NewBackendTLSPlugin(agw *AgwCollections) AgwPlugin {
	clusterDomain := kubeutils.GetClusterDomainName()
	tlsPolicyCol := krt.NewManyCollection(agw.BackendTLSPolicies, func(krtctx krt.HandlerContext, btls *gwv1.BackendTLSPolicy) []AgwPolicy {
		return translatePoliciesForBackendTLS(krtctx, agw.ConfigMaps, agw.Backends, btls, clusterDomain)
	})
	configPolicyCol := krt.NewManyCollection(agw.BackendConfigPolicies, func(krtctx krt.HandlerContext, bcfg *v1alpha1.BackendConfigPolicy) []AgwPolicy {
		return translatePoliciesForBackendConfig(krtctx, agw.Backends, agw.Secrets, bcfg, clusterDomain)
	})
	policyCol := mergeTLSAndConfigPolicies(tlsPolicyCol, configPolicyCol)
	return AgwPlugin{
		ContributesPolicies: map[schema.GroupKind]PolicyPlugin{
			wellknown.BackendTLSPolicyGVK.GroupKind(): {
				Policies: policyCol,
			},
			wellknown.BackendConfigPolicyGVK.GroupKind(): {
				Policies: policyCol,
			},
		},
		ExtraHasSynced: func() bool {
			return policyCol.HasSynced()
		},
	}
}

// translatePoliciesForBackendTLS generates backend TLS policies
func translatePoliciesForBackendTLS(
	krtctx krt.HandlerContext,
	cfgmaps krt.Collection[*corev1.ConfigMap],
	backends krt.Collection[*v1alpha1.Backend],
	btls *gwv1.BackendTLSPolicy,
	clusterDomain string,
) []AgwPolicy {
	logger := logger.With("plugin_kind", "backendtls")
	var policies []AgwPolicy

	for _, target := range btls.Spec.TargetRefs {
		var policyTarget *api.PolicyTarget

		switch string(target.Kind) {
		case wellknown.BackendGVK.Kind:
			backendRef := types.NamespacedName{
				Name:      string(target.Name),
				Namespace: btls.Namespace,
			}
			backend := krt.FetchOne(krtctx, backends, krt.FilterObjectName(backendRef))
			if backend == nil || *backend == nil {
				logger.Error("backend not found; skipping policy", "backend", backendRef, "policy", kubeutils.NamespacedNameFrom(btls))
				continue
			}
			spec := (*backend).Spec
			if spec.AI != nil {
				switch {
				// Single provider backend
				case spec.AI.LLM != nil:
					if target.SectionName != nil {
						logger.Error("sectionName must be omitted when targeting AI backend with single provider; skipping policy", "backend", backendRef, "policy", kubeutils.NamespacedNameFrom(btls))
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
								Backend: utils.InternalBackendName(btls.Namespace, string(target.Name), ""),
							},
						}
					}
				default:
					logger.Warn("unknown backend type", "backend", backendRef, "policy", kubeutils.NamespacedNameFrom(btls))
					continue
				}
			} else {
				// The target defaults to <backend-namespace>/<backend-name>.
				// If SectionName is specified to select a specific target in the Backend,
				// the target becomes <backend-namespace>/<backend-name>/<section-name>
				policyTarget = &api.PolicyTarget{
					Kind: &api.PolicyTarget_Backend{
						Backend: utils.InternalBackendName(btls.Namespace, string(target.Name), string(ptr.OrEmpty(target.SectionName))),
					},
				}
			}
		case wellknown.ServiceKind:
			hostname := fmt.Sprintf("%s.%s.svc.%s", target.Name, btls.Namespace, clusterDomain)
			// If SectionName is specified to select the port, use service/<namespace>/<hostname>:<port>
			if port := ptr.OrEmpty(target.SectionName); port != "" {
				policyTarget = &api.PolicyTarget{
					Kind: &api.PolicyTarget_Backend{
						Backend: fmt.Sprintf("service/%s/%s:%s", btls.Namespace, hostname, port),
					},
				}
			} else {
				// Select the entire service with <namespace>/<hostname>
				policyTarget = &api.PolicyTarget{
					Kind: &api.PolicyTarget_Service{
						Service: fmt.Sprintf("%s/%s", btls.Namespace, hostname),
					},
				}
			}

		default:
			logger.Warn("unsupported target kind", "kind", target.Kind, "policy", btls.Name)
			continue
		}
		caCert, err := getBackendTLSCACert(krtctx, cfgmaps, btls)
		if err != nil {
			logger.Error("error getting backend TLS CA cert", "policy", kubeutils.NamespacedNameFrom(btls), "error", err)
			return nil
		}

		policy := &api.Policy{
			Name:   btls.Namespace + "/" + btls.Name + ":backendtls" + attachmentName(policyTarget),
			Target: policyTarget,
			Spec: &api.PolicySpec{Kind: &api.PolicySpec_BackendTls{
				BackendTls: &api.PolicySpec_BackendTLS{
					Root: caCert,
					// Used for mTLS, not part of the spec currently
					Cert: nil,
					Key:  nil,
					// Not currently in the spec.
					Insecure: nil,
					// Validation.Hostname is a required value and validated with CEL
					Hostname: wrapperspb.String(string(btls.Spec.Validation.Hostname)),
				},
			}},
		}
		policies = append(policies, AgwPolicy{policy})
	}

	return policies
}

func getBackendTLSCACert(
	krtctx krt.HandlerContext,
	cfgmaps krt.Collection[*corev1.ConfigMap],
	btls *gwv1.BackendTLSPolicy,
) (*wrapperspb.BytesValue, error) {
	validation := btls.Spec.Validation
	if wk := validation.WellKnownCACertificates; wk != nil {
		switch kind := *wk; kind {
		case gwv1.WellKnownCACertificatesSystem:
			return nil, nil

		default:
			return nil, fmt.Errorf("unsupported wellKnownCACertificates: %v", kind)
		}
	}

	// One of WellKnownCACertificates or CACertificateRefs will always be specified (CEL validated)
	if len(validation.CACertificateRefs) == 0 {
		// should never happen as this is CEL validated. Only here to prevent panic in tests
		return nil, errors.New("BackendTLSPolicy must specify either wellKnownCACertificates or caCertificateRefs")
	}
	var sb strings.Builder
	for _, ref := range validation.CACertificateRefs {
		if ref.Group != gwv1.Group(wellknown.ConfigMapGVK.Group) || ref.Kind != gwv1.Kind(wellknown.ConfigMapGVK.Kind) {
			return nil, fmt.Errorf("BackendTLSPolicy's validation.caCertificateRefs must be a ConfigMap reference; got %s", ref)
		}
		nn := types.NamespacedName{
			Name:      string(ref.Name),
			Namespace: btls.Namespace,
		}
		cfgmap := krt.FetchOne(krtctx, cfgmaps, krt.FilterObjectName(nn))
		if cfgmap == nil {
			return nil, fmt.Errorf("ConfigMap %s not found", nn)
		}
		caCert, err := sslutils.GetCACertFromConfigMap(ptr.Flatten(cfgmap))
		if err != nil {
			return nil, fmt.Errorf("error extracting CA cert from ConfigMap %s: %w", nn, err)
		}
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(caCert)
	}
	return wrapperspb.Bytes([]byte(sb.String())), nil
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
		// TODO: need to verify this works, test failed when i added some.
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
	}, nil
}

// policyGroup holds policies grouped by target for merging
type policyGroup struct {
	tlsPolicies    []*api.Policy
	configPolicies []*api.Policy
}

// mergeTLSAndConfigPolicies merges TLS and config policies
// It uses a many-to-many aggregation pattern to merge the policies since a single policy can target multiple targets, and those must be matched with the other policies.
func mergeTLSAndConfigPolicies(tlsPolicyCol, configPolicyCol krt.Collection[AgwPolicy]) krt.Collection[AgwPolicy] {
	// using a static collection to support many-to-many aggregation of the different policies
	mergedCol := krt.NewStaticCollection[AgwPolicy](nil, nil, krt.WithName("MergedTLSPolicies"))

	// recompute and update the merged collection
	recomputeMerge := func() {
		policyGroups := groupPoliciesByTarget(tlsPolicyCol.List(), configPolicyCol.List())

		mergedPolicies := make([]AgwPolicy, 0, len(policyGroups))
		for targetKey, group := range policyGroups {
			if mergedPolicy := createMergedPolicy(targetKey, group); mergedPolicy != nil {
				mergedPolicies = append(mergedPolicies, AgwPolicy{Policy: mergedPolicy})
			}
		}

		mergedCol.Reset(mergedPolicies)
	}

	// Register handlers on both source collections to recompute on any change
	// This makes the collection reactive - any add/update/delete triggers recomputation
	onUpdate := func([]krt.Event[AgwPolicy]) { recomputeMerge() }
	tlsPolicyCol.RegisterBatch(onUpdate, false)
	configPolicyCol.RegisterBatch(onUpdate, false)

	// Do initial computation to populate the collection
	recomputeMerge()

	return mergedCol
}

// groupPoliciesByTarget groups policies from both collections by their target key
func groupPoliciesByTarget(tlsPolicies, configPolicies []AgwPolicy) map[string]*policyGroup {
	policyGroups := make(map[string]*policyGroup)

	// Helper to add a policy to the appropriate group
	addPolicy := func(policy *api.Policy, isTLS bool) {
		targetKey := getTargetKey(policy)
		if targetKey == "" {
			return
		}

		if policyGroups[targetKey] == nil {
			policyGroups[targetKey] = &policyGroup{}
		}

		if isTLS {
			policyGroups[targetKey].tlsPolicies = append(policyGroups[targetKey].tlsPolicies, policy)
		} else {
			policyGroups[targetKey].configPolicies = append(policyGroups[targetKey].configPolicies, policy)
		}
	}

	// Group TLS policies
	for _, policy := range tlsPolicies {
		addPolicy(policy.Policy, true)
	}

	// Group config policies
	for _, policy := range configPolicies {
		addPolicy(policy.Policy, false)
	}

	return policyGroups
}

// createMergedPolicy creates a merged policy from a policy group, or returns the single policy if only one type exists
func createMergedPolicy(targetKey string, group *policyGroup) *api.Policy {
	hasTLS := len(group.tlsPolicies) > 0
	hasConfig := len(group.configPolicies) > 0

	// If we have both TLS and config policies, merge them
	if hasTLS && hasConfig {
		return mergePolicyGroupByTarget(targetKey, group)
	}

	// If only one type exists, use the first one
	if hasTLS {
		return group.tlsPolicies[0]
	}
	if hasConfig {
		return group.configPolicies[0]
	}

	return nil
}

// getTargetKey creates a unique key for policy grouping based on target
func getTargetKey(policy *api.Policy) string {
	if policy.Target == nil || policy.Target.Kind == nil {
		return ""
	}

	switch t := policy.Target.Kind.(type) {
	case *api.PolicyTarget_Backend:
		return fmt.Sprintf("backend:%s", t.Backend)
	case *api.PolicyTarget_Service:
		return fmt.Sprintf("service:%s", t.Service)
	case *api.PolicyTarget_SubBackend:
		return fmt.Sprintf("subbackend:%s", t.SubBackend)
	default:
		return ""
	}
}

// mergePolicyGroupByTarget merges policies for the same target
func mergePolicyGroupByTarget(targetKey string, group *policyGroup) *api.Policy {
	if len(group.tlsPolicies) == 0 && len(group.configPolicies) == 0 {
		return nil
	}

	// Start with the first available policy as base
	var basePolicy *api.Policy
	if len(group.tlsPolicies) > 0 {
		basePolicy = group.tlsPolicies[0]
	} else if len(group.configPolicies) > 0 {
		basePolicy = group.configPolicies[0]
	} else {
		return nil
	}

	// Create merged BackendTLS spec
	mergedTLS := &api.PolicySpec_BackendTLS{}

	// Merge CA certificate from TLS policies (BackendTLSPolicy)
	for _, tlsPolicy := range group.tlsPolicies {
		if tlsPolicy.Spec.Kind != nil {
			if backendTls, ok := tlsPolicy.Spec.Kind.(*api.PolicySpec_BackendTls); ok && backendTls.BackendTls != nil {
				// Merge CA certificate if present
				if backendTls.BackendTls.Root != nil {
					mergedTLS.Root = backendTls.BackendTls.Root
				}
				// Merge hostname if present
				if backendTls.BackendTls.Hostname != nil {
					mergedTLS.Hostname = backendTls.BackendTls.Hostname
				}
				break // Use the first TLS policy's settings
			}
		}
	}

	// Merge client certificates from config policies (BackendConfigPolicy)
	for _, configPolicy := range group.configPolicies {
		if configPolicy.Spec.Kind != nil {
			if backendTls, ok := configPolicy.Spec.Kind.(*api.PolicySpec_BackendTls); ok && backendTls.BackendTls != nil {
				// Merge client certificates if present
				if backendTls.BackendTls.Cert != nil {
					mergedTLS.Cert = backendTls.BackendTls.Cert
				}
				if backendTls.BackendTls.Key != nil {
					mergedTLS.Key = backendTls.BackendTls.Key
				}
				// Merge hostname if not already set
				if mergedTLS.Hostname == nil && backendTls.BackendTls.Hostname != nil {
					mergedTLS.Hostname = backendTls.BackendTls.Hostname
				}
			}
		}
	}

	// Create final merged policy with a predictable name
	policyName := fmt.Sprintf("merged-tls-policy:%s", targetKey)

	return &api.Policy{
		Name:   policyName,
		Target: basePolicy.Target,
		Spec: &api.PolicySpec{Kind: &api.PolicySpec_BackendTls{
			BackendTls: mergedTLS,
		}},
	}
}
