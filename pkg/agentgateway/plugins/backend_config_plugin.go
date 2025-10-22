package plugins

import (
	"fmt"
	"os"

	"slices"
	"strings"

	"github.com/agentgateway/agentgateway/go/api"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8sptr "k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/wellknown"
	"github.com/kgateway-dev/kgateway/v2/pkg/agentgateway/utils"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/reporter"
	"github.com/kgateway-dev/kgateway/v2/pkg/reports"
	"github.com/kgateway-dev/kgateway/v2/pkg/utils/kubeutils"
)

// mapping of unsupported backendconfigpolicy fields to check if any are in use
var unsupportedBackendConfigPolicyFields = map[string]func(*v1alpha1.BackendConfigPolicy) bool{
	"TargetSelectors":               func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.TargetSelectors != nil },
	"ConnectTimeout":                func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.ConnectTimeout != nil },
	"PerConnectionBufferLimitBytes": func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.PerConnectionBufferLimitBytes != nil },
	"TCPKeepalive":                  func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.TCPKeepalive != nil },
	"CommonHttpProtocolOptions":     func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.CommonHttpProtocolOptions != nil },
	"Http1ProtocolOptions":          func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.Http1ProtocolOptions != nil },
	"Http2ProtocolOptions":          func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.Http2ProtocolOptions != nil },
	"LoadBalancer":                  func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.LoadBalancer != nil },
	"HealthCheck":                   func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.HealthCheck != nil },
	"OutlierDetection":              func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.OutlierDetection != nil },
	"TLS.WellKnownCACertificates": func(b *v1alpha1.BackendConfigPolicy) bool {
		return b.Spec.TLS != nil && b.Spec.TLS.WellKnownCACertificates != nil
	},
	"TLS.InsecureSkipVerify": func(b *v1alpha1.BackendConfigPolicy) bool {
		return b.Spec.TLS != nil && b.Spec.TLS.InsecureSkipVerify != nil
	},
	"TLS.VerifySubjectAltNames": func(b *v1alpha1.BackendConfigPolicy) bool {
		return b.Spec.TLS != nil && b.Spec.TLS.VerifySubjectAltNames != nil
	},
	"TLS.Parameters": func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.TLS != nil && b.Spec.TLS.Parameters != nil },
	"TLS.AlpnProtocols": func(b *v1alpha1.BackendConfigPolicy) bool {
		return b.Spec.TLS != nil && b.Spec.TLS.AlpnProtocols != nil
	},
	"TLS.AllowRenegotiation": func(b *v1alpha1.BackendConfigPolicy) bool {
		return b.Spec.TLS != nil && b.Spec.TLS.AllowRenegotiation != nil
	},
	"TLS.SimpleTLS": func(b *v1alpha1.BackendConfigPolicy) bool { return b.Spec.TLS != nil && b.Spec.TLS.SimpleTLS != nil },
}

// NewBackendConfigPlugin creates a new BackendConfigPolicy plugin
func NewBackendConfigPlugin(agw *AgwCollections) AgwPlugin {
	clusterDomain := kubeutils.GetClusterDomainName()
	policyStatusCol, policyCol := krt.NewStatusManyCollection(agw.BackendConfigPolicies, func(krtctx krt.HandlerContext, bcfg *v1alpha1.BackendConfigPolicy) (
		*gwv1.PolicyStatus,
		[]AgwPolicy,
	) {
		return translatePoliciesForBackendConfig(krtctx, agw.Backends, agw.Secrets, bcfg, clusterDomain, agw.ControllerName)
	})
	return AgwPlugin{
		ContributesPolicies: map[schema.GroupKind]PolicyPlugin{
			wellknown.BackendConfigPolicyGVK.GroupKind(): {
				Policies:       policyCol,
				PolicyStatuses: utils.ConvertStatusCollection(policyStatusCol),
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
	clusterDomain, controllerName string,
) (*gwv1.PolicyStatus, []AgwPolicy) {
	logger := logger.With("plugin_kind", "backendconfig")
	var policies []AgwPolicy
	var ancestors []gwv1.PolicyAncestorStatus

	for _, target := range bcfg.Spec.TargetRefs {
		var policyTarget *api.PolicyTarget
		// Build a base ParentRef for status reporting
		parentRef := gwv1.ParentReference{
			Name:      gwv1.ObjectName(target.Name),
			Namespace: k8sptr.To(gwv1.Namespace(bcfg.Namespace)),
		}
		if target.SectionName != nil {
			parentRef.SectionName = (*gwv1.SectionName)(target.SectionName)
		}

		switch string(target.Kind) {
		case wellknown.BackendGVK.Kind:
			// kgateway backend kind (MCP, AI, etc.)
			group := gwv1.Group(wellknown.BackendGVK.Group)
			kind := gwv1.Kind(wellknown.BackendGVK.Kind)
			parentRef.Group = &group
			parentRef.Kind = &kind

			backendKey := utils.GetBackendKey(bcfg.Namespace, string(target.Name))
			backend := krt.FetchOne(krtctx, backends, krt.FilterKey(backendKey))
			if backend == nil {
				logger.Error("backend not found",
					"target", target.Name,
					"policy", client.ObjectKeyFromObject(bcfg))

				conds := []metav1.Condition{}
				meta.SetStatusCondition(&conds, metav1.Condition{
					Type:    string(v1alpha1.PolicyConditionAccepted),
					Status:  metav1.ConditionFalse,
					Reason:  string(v1alpha1.PolicyReasonInvalid),
					Message: fmt.Sprintf("Backend %s not found", target.Name),
				})
				if controllerName != "" && string(parentRef.Name) != "" {
					ancestors = append(ancestors, gwv1.PolicyAncestorStatus{
						AncestorRef:    parentRef,
						ControllerName: v1alpha2.GatewayController(controllerName),
						Conditions:     conds,
					})
				}
				continue
			}
			spec := (*backend).Spec
			if spec.AI != nil {
				switch {
				// Single provider backend
				case spec.AI.LLM != nil:
					if target.SectionName != nil {
						logger.Error("sectionName must be omitted when targeting AI backend with single provider; skipping policy", "backend", backendKey, "policy", kubeutils.NamespacedNameFrom(bcfg))
						continue
					}
					// Single provider backends also use api.ProviderGroups(ref: buildAIIr), so policies must be applied per-provider using PolicyTarget_SubBackend
					policyTarget = &api.PolicyTarget{
						Kind: &api.PolicyTarget_SubBackend{
							SubBackend: utils.InternalBackendName(bcfg.Namespace, string(target.Name), utils.SingularLLMProviderSubBackendName),
						},
					}
				// Multi-provider backend
				case len(spec.AI.PriorityGroups) > 0:
					if target.SectionName != nil {
						// target SubBackend
						policyTarget = &api.PolicyTarget{
							Kind: &api.PolicyTarget_SubBackend{
								SubBackend: utils.InternalBackendName(bcfg.Namespace, string(target.Name), string(*target.SectionName)),
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
					logger.Warn("unknown backend type", "backend", backendKey, "policy", kubeutils.NamespacedNameFrom(bcfg))
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

		if policyTarget != nil {
			translatedPolicies, err := translateBackendConfigPolicyToAgw(krtctx, secrets, bcfg, policyTarget)
			policies = append(policies, translatedPolicies...)

			var conds []metav1.Condition
			if err != nil {
				meta.SetStatusCondition(&conds, metav1.Condition{
					Type:    string(v1alpha1.PolicyConditionAccepted),
					Status:  metav1.ConditionFalse,
					Reason:  string(v1alpha1.PolicyReasonInvalid),
					Message: err.Error(),
				})
			} else {
				meta.SetStatusCondition(&conds, metav1.Condition{
					Type:    string(v1alpha1.PolicyConditionAccepted),
					Status:  metav1.ConditionTrue,
					Reason:  string(v1alpha1.PolicyReasonValid),
					Message: reporter.PolicyAcceptedMsg,
				})
			}
			meta.SetStatusCondition(&conds, metav1.Condition{
				Type:    string(v1alpha1.PolicyConditionAttached),
				Status:  metav1.ConditionTrue,
				Reason:  string(v1alpha1.PolicyReasonAttached),
				Message: reporter.PolicyAttachedMsg,
			})
			// Set LastTransitionTime for all conditions
			for i := range conds {
				if conds[i].LastTransitionTime.IsZero() {
					conds[i].LastTransitionTime = metav1.Now()
				}
			}
			// Only append valid ancestors: require non-empty controllerName and parentRef name
			if controllerName != "" && string(parentRef.Name) != "" {
				ancestors = append(ancestors, gwv1.PolicyAncestorStatus{
					AncestorRef:    parentRef,
					ControllerName: v1alpha2.GatewayController(controllerName),
					Conditions:     conds,
				})
			}
		}
	}

	status := gwv1.PolicyStatus{Ancestors: ancestors}

	if len(status.Ancestors) > 15 {
		ignored := status.Ancestors[15:]
		status.Ancestors = status.Ancestors[:15]
		status.Ancestors = append(status.Ancestors, gwv1.PolicyAncestorStatus{
			AncestorRef: gwv1.ParentReference{
				Group: k8sptr.To(gwv1.Group("gateway.kgateway.dev")),
				Name:  "StatusSummary",
			},
			ControllerName: gwv1.GatewayController(controllerName),
			Conditions: []metav1.Condition{
				{
					Type:    "StatusSummarized",
					Status:  metav1.ConditionTrue,
					Reason:  "StatusSummary",
					Message: fmt.Sprintf("%d AncestorRefs ignored due to max status size", len(ignored)),
				},
			},
		})
	}

	slices.SortStableFunc(status.Ancestors, func(a, b gwv1.PolicyAncestorStatus) int {
		return strings.Compare(reports.ParentString(a.AncestorRef), reports.ParentString(b.AncestorRef))
	})

	return &status, policies
}

func translateBackendConfigPolicyToAgw(krtctx krt.HandlerContext, secrets krt.Collection[*corev1.Secret], bcfg *v1alpha1.BackendConfigPolicy, policyTarget *api.PolicyTarget) ([]AgwPolicy, error) {
	agwPolicies := make([]AgwPolicy, 0)

	// translate the TLS policy
	tlsPolicy, err := translateBackendTlsPolicy(krtctx, secrets, bcfg, policyTarget)
	if err != nil {
		return agwPolicies, err
	}
	agwPolicies = append(agwPolicies, *tlsPolicy)

	// report a status for unsupported field usage
	if unsupportedFields := checkUnsupportedBackendConfigPolicyFields(bcfg); len(unsupportedFields) > 0 {
		return agwPolicies, fmt.Errorf("unsupported fields: %s", strings.Join(unsupportedFields, ", "))
	}

	return agwPolicies, nil
}

func translateBackendTlsPolicy(krtctx krt.HandlerContext, secrets krt.Collection[*corev1.Secret], bcfg *v1alpha1.BackendConfigPolicy, policyTarget *api.PolicyTarget) (*AgwPolicy, error) {
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

	policy := &api.Policy{
		Name:   bcfg.Namespace + "/" + bcfg.Name + ":backendtls" + attachmentName(policyTarget),
		Target: policyTarget,
		Spec: &api.PolicySpec{
			Kind: &api.PolicySpec_BackendTls{
				BackendTls: &api.PolicySpec_BackendTLS{
					Cert:     cert,
					Key:      key,
					Hostname: hostname,
					// No mTLS support yet
					Insecure: wrapperspb.Bool(true),
				},
			},
		},
	}

	return &AgwPolicy{policy}, nil
}

func checkUnsupportedBackendConfigPolicyFields(bcfg *v1alpha1.BackendConfigPolicy) []string {
	var unsupportedFields []string
	for fieldName, checkFunc := range unsupportedBackendConfigPolicyFields {
		if checkFunc(bcfg) {
			unsupportedFields = append(unsupportedFields, fieldName)
		}
	}

	// sort for consistent reporting
	slices.Sort(unsupportedFields)

	return unsupportedFields
}
