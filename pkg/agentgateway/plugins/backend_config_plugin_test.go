package plugins

import (
	"testing"
	"time"

	"istio.io/istio/pkg/kube/krt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/wellknown"
)

func TestTranslatePoliciesForBackendConfig(t *testing.T) {
	krtctx := krt.TestingDummyContext{}

	// Create test backend
	backend := &v1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: v1alpha1.BackendSpec{
			Type: v1alpha1.BackendTypeStatic,
			Static: &v1alpha1.StaticBackend{
				Hosts: []v1alpha1.Host{
					{
						Host: "example.com",
						Port: 443,
					},
				},
			},
		},
	}

	// Create test secret with client certificate
	clientCert := `-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUG9Mdv3nOQ2i7v68OgjArU4lhBikwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjUwNzA3MTA0MDQwWhcNMjYw
NzA3MTA0MDQwWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANueqwfAApjTfg+nxIoKVK4sK/YlNICvdoEq1UEL
StE9wfTv0J27uNIsfpMqCx0Ni9Rjt1hzjunc8HUJDeobMNxGaZmryQofrdJWJ7Uu
t5jeLW/w0MelPOfFLsDiM5REy4WuPm2X6v1Z1N3N5GR3UNDOtDtsbjS1momvooLO
9WxPIr2cfmPqr81fyyD2ReZsMC/8lVs0PkA9XBplMzpSU53DWl5/Nyh2d1W5ENK0
Zw1l5Ze4UGUeohQMa5cD5hmZcBjOeJF8MuSTi3167KSopoqfgHTvC5IsBeWXAyZF
81ihFYAq+SbhUZeUlsxc1wveuAdBRzafcYkK47gYmbq1K60CAwEAAaNbMFkwFgYD
VR0RBA8wDYILZXhhbXBsZS5jb20wCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMB0GA1UdDgQWBBSoa1Zu2o+pQ6sq2HcOjAglZkp01zANBgkqhkiG9w0B
AQsFAAOCAQEADZq1EMw/jMl0z2LpPh8cXbP09BnfXhoFbpL4cFrcBNEyig0oPO0j
YN1e4bfURNduFVnC/FDnZhR3FlAt8a6ozJAwmJp+nQCYFoDQwotSx12y5Bc9IXwd
BRZaLgHYy2NjGp2UgAya2z23BkUnwOJwJNMCzuGw3pOsmDQY0diR8ZWmEYYEPheW
6BVkrikzUNXv3tB8LmWzxV9V3eN71fnP5u39IM/UQsOZGRUow/8tvN2/d0W4dHky
t/kdgLKhf4gU2wXq/WbeqxlDSpjo7q/emNl59v1FHeR3eITSSjESU+dQgRsYaGEn
SWP+58ApfCcURLpMxUmxkO1ayfecNJbmSQ==
-----END CERTIFICATE-----`
	privateKey := `-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA0wQ2HH4HH4HH4HH4H
H4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4H
H4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4H
H4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4H
-----END PRIVATE KEY-----`

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "client-tls-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte(clientCert),
			corev1.TLSPrivateKeyKey: []byte(privateKey),
		},
	}

	tests := []struct {
		name          string
		policy        *v1alpha1.BackendConfigPolicy
		backends      []*v1alpha1.Backend
		secrets       []*corev1.Secret
		clusterDomain string
		validate      func(t *testing.T, policies []AgwPolicy, status *gwv1.PolicyStatus)
	}{
		{
			name: "valid BackendConfigPolicy targeting Backend with TLS",
			policy: &v1alpha1.BackendConfigPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "config-policy",
					Namespace: "default",
				},
				Spec: v1alpha1.BackendConfigPolicySpec{
					TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  gwv1.ObjectName("test-backend"),
							},
						},
					},
					TLS: &v1alpha1.TLS{
						SecretRef: &corev1.LocalObjectReference{
							Name: "client-tls-secret",
						},
						Sni: ptr.To("example.com"),
					},
				},
			},
			backends:      []*v1alpha1.Backend{backend},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, status *gwv1.PolicyStatus) {
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				assert.Equal(t, "default/config-policy:backendtls:default/test-backend", policy.Name)
				assert.NotNil(t, policy.Target)

				backendTarget := policy.Target.GetBackend()
				assert.Equal(t, "default/test-backend", backendTarget)

				backendTLSSpec := policy.Spec.GetBackendTls()
				require.NotNil(t, backendTLSSpec)
				assert.NotNil(t, backendTLSSpec.Cert)
				assert.NotNil(t, backendTLSSpec.Key)
				assert.Equal(t, "example.com", backendTLSSpec.Hostname.GetValue())

				// status should be accepted
				require.NotNil(t, status)
				require.Len(t, status.Ancestors, 1)
				ancestor := status.Ancestors[0]
				assert.Equal(t, "test-backend", string(ancestor.AncestorRef.Name))
				conditions := mapConditions(ancestor.Conditions)
				assert.Equal(t, metav1.ConditionTrue, conditions[string(v1alpha1.PolicyConditionAccepted)].Status)
				assert.Equal(t, metav1.ConditionTrue, conditions[string(v1alpha1.PolicyConditionAttached)].Status)
			},
		},
		{
			name: "BackendConfigPolicy with missing secret",
			policy: &v1alpha1.BackendConfigPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "missing-secret-policy",
					Namespace: "default",
				},
				Spec: v1alpha1.BackendConfigPolicySpec{
					TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  gwv1.ObjectName("test-backend"),
							},
						},
					},
					TLS: &v1alpha1.TLS{
						SecretRef: &corev1.LocalObjectReference{
							Name: "missing-secret",
						},
					},
				},
			},
			backends:      []*v1alpha1.Backend{backend},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, status *gwv1.PolicyStatus) {
				assert.Len(t, policies, 0)
				require.NotNil(t, status)
				require.Len(t, status.Ancestors, 1)
				ancestor := status.Ancestors[0]
				assert.Equal(t, "test-backend", string(ancestor.AncestorRef.Name))
				conditions := mapConditions(ancestor.Conditions)
				assert.Equal(t, metav1.ConditionFalse, conditions[string(v1alpha1.PolicyConditionAccepted)].Status)
				assert.Contains(t, conditions[string(v1alpha1.PolicyConditionAccepted)].Message, "TLS secret not found")
			},
		},
		{
			name: "BackendConfigPolicy with multiple existing target refs",
			policy: &v1alpha1.BackendConfigPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "multiple-target-refs-policy",
					Namespace: "default",
				},
				Spec: v1alpha1.BackendConfigPolicySpec{
					TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  gwv1.ObjectName("test-backend"),
							},
						},
						{
							LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  gwv1.ObjectName("test-backend2"),
							},
						},
					},
					TLS: &v1alpha1.TLS{
						SecretRef: &corev1.LocalObjectReference{
							Name: "client-tls-secret",
						},
						Sni: ptr.To("example.com"),
					},
				},
			},
			backends: []*v1alpha1.Backend{backend, {
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backend2",
					Namespace: "default",
				},
				Spec: v1alpha1.BackendSpec{
					Type: v1alpha1.BackendTypeStatic,
					Static: &v1alpha1.StaticBackend{
						Hosts: []v1alpha1.Host{
							{
								Host: "example2.com",
								Port: 443,
							},
						},
					},
				},
			}},
			secrets:       []*corev1.Secret{secret, secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, status *gwv1.PolicyStatus) {
				require.Len(t, policies, 2)

				// Check that both policies have correct names
				policyNames := make(map[string]bool)
				for _, policy := range policies {
					policyNames[policy.Policy.Name] = true
				}
				assert.True(t, policyNames["default/multiple-target-refs-policy:backendtls:default/test-backend"])
				assert.True(t, policyNames["default/multiple-target-refs-policy:backendtls:default/test-backend2"])

				// Check status has two ancestors (one per target ref)
				require.NotNil(t, status)
				require.Len(t, status.Ancestors, 2)

				ancestor1, ancestor2 := status.Ancestors[0], status.Ancestors[1]

				assert.Equal(t, "test-backend", string(ancestor1.AncestorRef.Name))
				assert.Equal(t, "test-backend2", string(ancestor2.AncestorRef.Name))

				conditions1 := mapConditions(ancestor1.Conditions)
				assert.Equal(t, metav1.ConditionTrue, conditions1[string(v1alpha1.PolicyConditionAccepted)].Status)
				assert.Equal(t, metav1.ConditionTrue, conditions1[string(v1alpha1.PolicyConditionAttached)].Status)

				conditions2 := mapConditions(ancestor2.Conditions)
				assert.Equal(t, metav1.ConditionTrue, conditions2[string(v1alpha1.PolicyConditionAccepted)].Status)
				assert.Equal(t, metav1.ConditionTrue, conditions2[string(v1alpha1.PolicyConditionAttached)].Status)
			},
		},
		{
			name: "BackendConfigPolicy with a non-existing target ref",
			policy: &v1alpha1.BackendConfigPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "multiple-target-refs-policy",
					Namespace: "default",
				},
				Spec: v1alpha1.BackendConfigPolicySpec{
					TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  gwv1.ObjectName("test-backend"),
							},
						},
						{
							LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  gwv1.ObjectName("test-backend2"),
							},
						},
					},
					TLS: &v1alpha1.TLS{
						SecretRef: &corev1.LocalObjectReference{
							Name: "client-tls-secret",
						},
						Sni: ptr.To("example.com"),
					},
				},
			},
			backends:      []*v1alpha1.Backend{backend},
			secrets:       []*corev1.Secret{secret, secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, status *gwv1.PolicyStatus) {
				require.Len(t, policies, 1)

				// Check that only the existing target ref is translated
				assert.Equal(t, "default/multiple-target-refs-policy:backendtls:default/test-backend", policies[0].Policy.Name)

				// Check status has two ancestors (one per target ref)
				require.NotNil(t, status)
				require.Len(t, status.Ancestors, 2)

				ancestor1, ancestor2 := status.Ancestors[0], status.Ancestors[1]

				assert.Equal(t, "test-backend", string(ancestor1.AncestorRef.Name))
				assert.Equal(t, "test-backend2", string(ancestor2.AncestorRef.Name))

				conditions1 := mapConditions(ancestor1.Conditions)
				assert.Equal(t, metav1.ConditionTrue, conditions1[string(v1alpha1.PolicyConditionAccepted)].Status)
				assert.Equal(t, metav1.ConditionTrue, conditions1[string(v1alpha1.PolicyConditionAttached)].Status)

				conditions2 := mapConditions(ancestor2.Conditions)
				assert.Equal(t, metav1.ConditionFalse, conditions2[string(v1alpha1.PolicyConditionAccepted)].Status)
				assert.Contains(t, conditions2[string(v1alpha1.PolicyConditionAccepted)].Message, "not found")
			},
		},
		{
			name: "BackendConfigPolicy with unsupported fields - should translate but have error status",
			policy: &v1alpha1.BackendConfigPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unsupported-fields-policy",
					Namespace: "default",
				},
				// Add unsupported fields: ConnectTimeout + TLS.SimpleTLS
				Spec: v1alpha1.BackendConfigPolicySpec{
					TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  gwv1.ObjectName("test-backend"),
							},
						},
					},
					TLS: &v1alpha1.TLS{
						SecretRef: &corev1.LocalObjectReference{
							Name: "client-tls-secret",
						},
						Sni:       ptr.To("example.com"),
						SimpleTLS: ptr.To(true),
					},
					ConnectTimeout: &metav1.Duration{
						Duration: time.Second * 5,
					},
				},
			},
			backends:      []*v1alpha1.Backend{backend},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, status *gwv1.PolicyStatus) {
				// Policy should still be translated even with unsupported fields
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				assert.Equal(t, "default/unsupported-fields-policy:backendtls:default/test-backend", policy.Name)
				assert.NotNil(t, policy.Target)

				backendTarget := policy.Target.GetBackend()
				assert.Equal(t, "default/test-backend", backendTarget)

				// Check that TLS config is still applied
				backendTLSSpec := policy.Spec.GetBackendTls()
				require.NotNil(t, backendTLSSpec)
				assert.NotNil(t, backendTLSSpec.Cert)
				assert.NotNil(t, backendTLSSpec.Key)
				assert.Equal(t, "example.com", backendTLSSpec.Hostname.GetValue())

				// Status should show error due to unsupported fields
				require.NotNil(t, status)
				require.Len(t, status.Ancestors, 1)
				ancestor := status.Ancestors[0]
				assert.Equal(t, "test-backend", string(ancestor.AncestorRef.Name))
				conditions := mapConditions(ancestor.Conditions)
				assert.Equal(t, metav1.ConditionFalse, conditions[string(v1alpha1.PolicyConditionAccepted)].Status)
				assert.Contains(t, conditions[string(v1alpha1.PolicyConditionAccepted)].Message, "unsupported fields: ConnectTimeout, TLS.SimpleTLS")
				assert.Equal(t, metav1.ConditionTrue, conditions[string(v1alpha1.PolicyConditionAttached)].Status)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create collections for testing
			backendsCol := krt.NewStaticCollection(nil, tt.backends)
			secretsCol := krt.NewStaticCollection(nil, tt.secrets)

			status, policies := translatePoliciesForBackendConfig(krtctx, backendsCol, secretsCol, tt.policy, tt.clusterDomain, "test-controller")

			if tt.validate != nil {
				tt.validate(t, policies, status)
			}
		})
	}
}

func mapConditions(conditions []metav1.Condition) map[string]metav1.Condition {
	conditionMap := make(map[string]metav1.Condition)
	for _, condition := range conditions {
		conditionMap[condition.Type] = condition
	}
	return conditionMap
}
