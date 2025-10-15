package plugins

import (
	"testing"

	"github.com/agentgateway/agentgateway/go/api"
	"istio.io/istio/pkg/kube/krt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/wellknown"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
)

// TODO: Add one with multiple target refs

func TestTranslatePoliciesForBackendTLS(t *testing.T) {
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

	// Create test ConfigMap with CA cert
	caCert := `-----BEGIN CERTIFICATE-----
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
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ca-cert",
			Namespace: "default",
		},
		Data: map[string]string{
			"ca.crt": caCert,
		},
	}

	tests := []struct {
		name          string
		policy        *gwv1.BackendTLSPolicy
		backends      []*v1alpha1.Backend
		configMaps    []*corev1.ConfigMap
		clusterDomain string
		wantErr       bool
		errContains   string
		validate      func(t *testing.T, policies []AgwPolicy, err error)
	}{
		{
			name: "valid BackendTLSPolicy targeting Backend",
			policy: &gwv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tls-policy",
					Namespace: "default",
				},
				Spec: gwv1.BackendTLSPolicySpec{
					TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  gwv1.ObjectName("test-backend"),
							},
						},
					},
					Validation: gwv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gwv1.LocalObjectReference{
							{
								Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
								Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
								Name:  "test-ca-cert",
							},
						},
						Hostname: "example.com",
					},
				},
			},
			backends:      []*v1alpha1.Backend{backend},
			configMaps:    []*corev1.ConfigMap{configMap},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				assert.Equal(t, "default/tls-policy:backendtls:default/test-backend", policy.Name)
				assert.NotNil(t, policy.Target)
				assert.NotNil(t, policy.Spec)

				backendTLSTarget := policy.Target.GetBackend()
				assert.Equal(t, "default/test-backend", backendTLSTarget)

				backendTLSSpec := policy.Spec.GetBackendTls()
				require.NotNil(t, backendTLSSpec)
				assert.NotNil(t, backendTLSSpec.Root)
				assert.Equal(t, "example.com", backendTLSSpec.Hostname.GetValue())
			},
		},
		{
			name: "BackendTLSPolicy targeting Service",
			policy: &gwv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "service-tls-policy",
					Namespace: "default",
				},
				Spec: gwv1.BackendTLSPolicySpec{
					TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
								Group: "",
								Kind:  gwv1.Kind(wellknown.ServiceKind),
								Name:  gwv1.ObjectName("test-service"),
							},
							SectionName: ptr.To(gwv1.SectionName("443")),
						},
					},
					Validation: gwv1.BackendTLSPolicyValidation{
						WellKnownCACertificates: (*gwv1.WellKnownCACertificatesType)(ptr.To(gwv1.WellKnownCACertificatesSystem)),
						Hostname:                "test-service.default.svc.cluster.local",
					},
				},
			},
			backends:      []*v1alpha1.Backend{backend},
			configMaps:    []*corev1.ConfigMap{configMap},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				assert.Equal(t, "default/service-tls-policy:backendtls:service/default/test-service.default.svc.cluster.local:443", policy.Name)
				assert.NotNil(t, policy.Target)

				backendTarget := policy.Target.GetBackend()
				assert.Equal(t, "service/default/test-service.default.svc.cluster.local:443", backendTarget)
			},
		},
		{
			name: "BackendTLSPolicy targeting AI Backend single provider",
			policy: &gwv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ai-tls-policy",
					Namespace: "default",
				},
				Spec: gwv1.BackendTLSPolicySpec{
					TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  "ai-backend",
							},
						},
					},
					Validation: gwv1.BackendTLSPolicyValidation{
						WellKnownCACertificates: (*gwv1.WellKnownCACertificatesType)(ptr.To(gwv1.WellKnownCACertificatesSystem)),
						Hostname:                "api.openai.com",
					},
				},
			},
			backends: []*v1alpha1.Backend{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ai-backend",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeAI,
						AI: &v1alpha1.AIBackend{
							LLM: &v1alpha1.LLMProvider{
								OpenAI: &v1alpha1.OpenAIConfig{
									AuthToken: v1alpha1.SingleAuthToken{
										Kind:   v1alpha1.Inline,
										Inline: ptr.To("test-token"),
									},
								},
							},
						},
					},
				},
			},
			configMaps:    []*corev1.ConfigMap{configMap},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				assert.Equal(t, "default/ai-tls-policy:backendtls:default/ai-backend/backend", policy.Name)
				assert.NotNil(t, policy.Target)

				subBackendTarget := policy.Target.GetSubBackend()
				assert.Equal(t, "default/ai-backend/backend", subBackendTarget)
			},
		},
		{
			name: "BackendTLSPolicy targeting AI Backend multi-provider with sectionName",
			policy: &gwv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ai-multi-tls-policy",
					Namespace: "default",
				},
				Spec: gwv1.BackendTLSPolicySpec{
					TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  "ai-multi-backend",
							},
							SectionName: ptr.To(gwv1.SectionName("openai-provider")),
						},
					},
					Validation: gwv1.BackendTLSPolicyValidation{
						WellKnownCACertificates: (*gwv1.WellKnownCACertificatesType)(ptr.To(gwv1.WellKnownCACertificatesSystem)),
						Hostname:                "api.openai.com",
					},
				},
			},
			backends: []*v1alpha1.Backend{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ai-multi-backend",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeAI,
						AI: &v1alpha1.AIBackend{
							PriorityGroups: []v1alpha1.PriorityGroup{
								{
									Providers: []v1alpha1.NamedLLMProvider{
										{
											Name: "openai-provider",
											LLMProvider: v1alpha1.LLMProvider{
												OpenAI: &v1alpha1.OpenAIConfig{
													AuthToken: v1alpha1.SingleAuthToken{
														Kind:   v1alpha1.Inline,
														Inline: ptr.To("test-token"),
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			configMaps:    []*corev1.ConfigMap{configMap},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				assert.Equal(t, "default/ai-multi-tls-policy:backendtls:default/ai-multi-backend/openai-provider", policy.Name)
				assert.NotNil(t, policy.Target)

				subBackendTarget := policy.Target.GetSubBackend()
				assert.Equal(t, "default/ai-multi-backend/openai-provider", subBackendTarget)
			},
		},
		{
			name: "BackendTLSPolicy with missing backend",
			policy: &gwv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "missing-backend-tls-policy",
					Namespace: "default",
				},
				Spec: gwv1.BackendTLSPolicySpec{
					TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  "missing-backend",
							},
						},
					},
					Validation: gwv1.BackendTLSPolicyValidation{
						WellKnownCACertificates: (*gwv1.WellKnownCACertificatesType)(ptr.To(gwv1.WellKnownCACertificatesSystem)),
						Hostname:                "example.com",
					},
				},
			},
			backends:      []*v1alpha1.Backend{backend},
			configMaps:    []*corev1.ConfigMap{configMap},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				// Should return empty policies when backend not found, no error returned
				assert.Len(t, policies, 0)
				assert.NoError(t, err)
			},
		},
		{
			name: "BackendTLSPolicy with missing ConfigMap",
			policy: &gwv1.BackendTLSPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "missing-ca-tls-policy",
					Namespace: "default",
				},
				Spec: gwv1.BackendTLSPolicySpec{
					TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
								Group: gwv1.Group(wellknown.BackendGVK.Group),
								Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
								Name:  gwv1.ObjectName("test-backend"),
							},
						},
					},
					Validation: gwv1.BackendTLSPolicyValidation{
						CACertificateRefs: []gwv1.LocalObjectReference{
							{
								Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
								Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
								Name:  "missing-ca-cert",
							},
						},
						Hostname: "example.com",
					},
				},
			},
			backends:      []*v1alpha1.Backend{backend},
			configMaps:    []*corev1.ConfigMap{configMap},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				// Should return empty policies when ConfigMap not found, no error returned
				assert.Len(t, policies, 0)
				assert.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create collections for testing
			backendsCol := krt.NewStaticCollection(nil, tt.backends)
			configMapsCol := krt.NewStaticCollection(nil, tt.configMaps)

			policies := translatePoliciesForBackendTLS(krtctx, configMapsCol, backendsCol, tt.policy, tt.clusterDomain)

			if tt.validate != nil {
				tt.validate(t, policies, nil)
			}
		})
	}
}

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
		wantErr       bool
		errContains   string
		validate      func(t *testing.T, policies []AgwPolicy, err error)
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
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				assert.Equal(t, "default/config-policy:backendconfig:default/test-backend", policy.Name)
				assert.NotNil(t, policy.Target)

				backendTarget := policy.Target.GetBackend()
				assert.Equal(t, "default/test-backend", backendTarget)

				backendTLSSpec := policy.Spec.GetBackendTls()
				require.NotNil(t, backendTLSSpec)
				assert.NotNil(t, backendTLSSpec.Cert)
				assert.NotNil(t, backendTLSSpec.Key)
				assert.Equal(t, "example.com", backendTLSSpec.Hostname.GetValue())
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
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				// Should return empty policies when secret not found, no error returned
				assert.Len(t, policies, 0)
				assert.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create collections for testing
			backendsCol := krt.NewStaticCollection(nil, tt.backends)
			secretsCol := krt.NewStaticCollection(nil, tt.secrets)

			policies := translatePoliciesForBackendConfig(krtctx, backendsCol, secretsCol, tt.policy, tt.clusterDomain)

			if tt.validate != nil {
				tt.validate(t, policies, nil)
			}
		})
	}
}

func TestMergeTLSAndConfigPolicies(t *testing.T) {
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

	// Create test ConfigMap with CA cert
	caCert := `-----BEGIN CERTIFICATE-----
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
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ca-cert",
			Namespace: "default",
		},
		Data: map[string]string{
			"ca.crt": caCert,
		},
	}

	// Create test secret with client certificate
	clientCert := []byte(`-----BEGIN CERTIFICATE-----
MIIB0jCCAXugAwIBAgIJAI7VCg4HH4HH4MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTQwNzE1MTgyOTU3WhcNMTUwNzE1MTgyOTU3WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANME
-----END CERTIFICATE-----`)
	privateKey := []byte(`-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA0wQ2HH4HH4HH4HH4H
H4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4H
H4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4H
H4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4HH4H
-----END PRIVATE KEY-----`)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "client-tls-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       clientCert,
			corev1.TLSPrivateKeyKey: privateKey,
		},
	}

	tests := []struct {
		name           string
		tlsPolicies    []*gwv1.BackendTLSPolicy
		configPolicies []*v1alpha1.BackendConfigPolicy
		backends       []*v1alpha1.Backend
		configMaps     []*corev1.ConfigMap
		secrets        []*corev1.Secret
		clusterDomain  string
		validate       func(t *testing.T, policies []AgwPolicy, err error)
	}{
		{
			name: "merge TLS and Config policies for same backend target - single backend",
			tlsPolicies: []*gwv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-policy",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("test-backend"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "example.com",
						},
					},
				},
			},
			configPolicies: []*v1alpha1.BackendConfigPolicy{
				{
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
			},
			backends:      []*v1alpha1.Backend{backend},
			configMaps:    []*corev1.ConfigMap{configMap},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				assert.Contains(t, policy.Name, "merged-tls-policy:backend:default/test-backend")
				assert.NotNil(t, policy.Target)

				backendTarget := policy.Target.GetBackend()
				assert.Equal(t, "default/test-backend", backendTarget)

				backendTLSSpec := policy.Spec.GetBackendTls()
				require.NotNil(t, backendTLSSpec)

				// Should have both CA cert (from TLS policy) and client cert (from config policy)
				assert.NotNil(t, backendTLSSpec.Root)
				assert.NotNil(t, backendTLSSpec.Cert)
				assert.NotNil(t, backendTLSSpec.Key)
				assert.Equal(t, "example.com", backendTLSSpec.Hostname.GetValue())
			},
		},
		{
			name: "only TLS policy - single backend",
			tlsPolicies: []*gwv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-only-policy",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("test-backend"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "example.com",
						},
					},
				},
			},
			configPolicies: nil,
			backends:       []*v1alpha1.Backend{backend},
			configMaps:     []*corev1.ConfigMap{configMap},
			secrets:        []*corev1.Secret{secret},
			clusterDomain:  "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				// Should use the original TLS policy name when no config policy to merge
				assert.Equal(t, "default/tls-only-policy:backendtls:default/test-backend", policy.Name)
				assert.NotNil(t, policy.Target)

				backendTLSSpec := policy.Spec.GetBackendTls()
				require.NotNil(t, backendTLSSpec)
				assert.NotNil(t, backendTLSSpec.Root)
				assert.Nil(t, backendTLSSpec.Cert)
				assert.Nil(t, backendTLSSpec.Key)
			},
		},
		{
			name:        "only Config policy - single backend",
			tlsPolicies: nil,
			configPolicies: []*v1alpha1.BackendConfigPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "config-only-policy",
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
			},
			backends:      []*v1alpha1.Backend{backend},
			configMaps:    []*corev1.ConfigMap{configMap},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 1)

				policy := policies[0].Policy
				// Should use the original config policy name when no TLS policy to merge
				assert.Equal(t, "default/config-only-policy:backendconfig:default/test-backend", policy.Name)
				assert.NotNil(t, policy.Target)

				backendTLSSpec := policy.Spec.GetBackendTls()
				require.NotNil(t, backendTLSSpec)
				assert.Nil(t, backendTLSSpec.Root)
				assert.NotNil(t, backendTLSSpec.Cert)
				assert.NotNil(t, backendTLSSpec.Key)
			},
		},
		{
			name:           "no policies",
			tlsPolicies:    nil,
			configPolicies: nil,
			backends:       []*v1alpha1.Backend{backend},
			configMaps:     []*corev1.ConfigMap{configMap},
			secrets:        []*corev1.Secret{secret},
			clusterDomain:  "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				assert.Len(t, policies, 0)
				assert.NoError(t, err)
			},
		},
		{
			name: "TLS policy and config policy targeting different backends",
			tlsPolicies: []*gwv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-policy-backend1",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend1"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "backend1.example.com",
						},
					},
				},
			},
			configPolicies: []*v1alpha1.BackendConfigPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "config-policy-backend2",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendConfigPolicySpec{
						TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend2"),
								},
							},
						},
						TLS: &v1alpha1.TLS{
							SecretRef: &corev1.LocalObjectReference{
								Name: "client-tls-secret",
							},
							Sni: ptr.To("backend2.example.com"),
						},
					},
				},
			},
			backends: []*v1alpha1.Backend{
				backend, // test-backend
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend1",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeStatic,
						Static: &v1alpha1.StaticBackend{
							Hosts: []v1alpha1.Host{
								{
									Host: "backend1.example.com",
									Port: 443,
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend2",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeStatic,
						Static: &v1alpha1.StaticBackend{
							Hosts: []v1alpha1.Host{
								{
									Host: "backend2.example.com",
									Port: 443,
								},
							},
						},
					},
				},
			},
			configMaps:    []*corev1.ConfigMap{configMap},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				// Should have separate policies for each backend
				require.Len(t, policies, 2)

				policyMap := make(map[string]*AgwPolicy)
				for _, policy := range policies {
					policyMap[policy.Policy.Name] = &policy
				}

				tlsPolicyBackend1 := policyMap["default/tls-policy-backend1:backendtls:default/backend1"]
				require.NotNil(t, tlsPolicyBackend1)
				require.NotNil(t, tlsPolicyBackend1.Policy.Spec.GetBackendTls())
				assert.Equal(t, "backend1.example.com", tlsPolicyBackend1.Policy.Spec.GetBackendTls().Hostname.GetValue())
				assert.NotNil(t, tlsPolicyBackend1.Policy.Spec.GetBackendTls().Root)
				assert.Nil(t, tlsPolicyBackend1.Policy.Spec.GetBackendTls().Cert)
				assert.Nil(t, tlsPolicyBackend1.Policy.Spec.GetBackendTls().Key)

				configPolicyBackend2 := policyMap["default/config-policy-backend2:backendconfig:default/backend2"]
				require.NotNil(t, configPolicyBackend2)
				require.NotNil(t, configPolicyBackend2.Policy.Spec.GetBackendTls())
				assert.Equal(t, "backend2.example.com", configPolicyBackend2.Policy.Spec.GetBackendTls().Hostname.GetValue())
				assert.Nil(t, configPolicyBackend2.Policy.Spec.GetBackendTls().Root)
				assert.NotNil(t, configPolicyBackend2.Policy.Spec.GetBackendTls().Cert)
				assert.NotNil(t, configPolicyBackend2.Policy.Spec.GetBackendTls().Key)
			},
		},
		{
			name: "two TLS policies and two config policies targeting two backends",
			tlsPolicies: []*gwv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-policy-backend1",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend1"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "backend1.example.com",
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-policy-backend2",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend2"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "backend2.example.com",
						},
					},
				},
			},
			configPolicies: []*v1alpha1.BackendConfigPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "config-policy-backend1",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendConfigPolicySpec{
						TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend1"),
								},
							},
						},
						TLS: &v1alpha1.TLS{
							SecretRef: &corev1.LocalObjectReference{
								Name: "client-tls-secret",
							},
							Sni: ptr.To("backend1.example.com"),
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "config-policy-backend2",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendConfigPolicySpec{
						TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend2"),
								},
							},
						},
						TLS: &v1alpha1.TLS{
							SecretRef: &corev1.LocalObjectReference{
								Name: "client-tls-secret",
							},
							Sni: ptr.To("backend2.example.com"),
						},
					},
				},
			},
			backends: []*v1alpha1.Backend{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend1",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeStatic,
						Static: &v1alpha1.StaticBackend{
							Hosts: []v1alpha1.Host{
								{
									Host: "backend1.example.com",
									Port: 443,
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend2",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeStatic,
						Static: &v1alpha1.StaticBackend{
							Hosts: []v1alpha1.Host{
								{
									Host: "backend2.example.com",
									Port: 443,
								},
							},
						},
					},
				},
			},
			configMaps:    []*corev1.ConfigMap{configMap},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 2)

				// Should have merged policies for each backend
				policyMap := make(map[string]*AgwPolicy)
				for _, policy := range policies {
					policyMap[policy.Policy.Name] = &policy
				}

				backend1Policy := policyMap["merged-tls-policy:backend:default/backend1"]
				require.NotNil(t, backend1Policy)
				require.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls())
				assert.Equal(t, "backend1.example.com", backend1Policy.Policy.Spec.GetBackendTls().Hostname.GetValue())
				assert.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls().Root)
				assert.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls().Cert)
				assert.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls().Key)

				backend2Policy := policyMap["merged-tls-policy:backend:default/backend2"]
				require.NotNil(t, backend2Policy)
				require.NotNil(t, backend2Policy.Policy.Spec.GetBackendTls())
				assert.Equal(t, "backend2.example.com", backend2Policy.Policy.Spec.GetBackendTls().Hostname.GetValue())
				assert.NotNil(t, backend2Policy.Policy.Spec.GetBackendTls().Root)
				assert.NotNil(t, backend2Policy.Policy.Spec.GetBackendTls().Cert)
				assert.NotNil(t, backend2Policy.Policy.Spec.GetBackendTls().Key)
			},
		},
		{
			name: "two TLS policies and one config policy targeting two backends (one without match)",
			tlsPolicies: []*gwv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-policy-backend1",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend1"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "backend1.example.com",
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-policy-backend2",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend2"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "backend2.example.com",
						},
					},
				},
			},
			configPolicies: []*v1alpha1.BackendConfigPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "config-policy-backend1-only",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendConfigPolicySpec{
						TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend1"),
								},
							},
						},
						TLS: &v1alpha1.TLS{
							SecretRef: &corev1.LocalObjectReference{
								Name: "client-tls-secret",
							},
							Sni: ptr.To("backend1.example.com"),
						},
					},
				},
			},
			backends: []*v1alpha1.Backend{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend1",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeStatic,
						Static: &v1alpha1.StaticBackend{
							Hosts: []v1alpha1.Host{
								{
									Host: "backend1.example.com",
									Port: 443,
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend2",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeStatic,
						Static: &v1alpha1.StaticBackend{
							Hosts: []v1alpha1.Host{
								{
									Host: "backend2.example.com",
									Port: 443,
								},
							},
						},
					},
				},
			},
			configMaps:    []*corev1.ConfigMap{configMap},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 2)

				// Should have one merged policy for backend1 and one TLS-only policy for backend2
				policyMap := make(map[string]*AgwPolicy)
				for _, policy := range policies {
					policyMap[policy.Policy.Name] = &policy
				}

				backend1Policy := policyMap["merged-tls-policy:backend:default/backend1"]
				require.NotNil(t, backend1Policy)
				require.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls())
				assert.Equal(t, "backend1.example.com", backend1Policy.Policy.Spec.GetBackendTls().Hostname.GetValue())
				assert.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls().Root)
				assert.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls().Cert)
				assert.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls().Key)

				backend2Policy := policyMap["default/tls-policy-backend2:backendtls:default/backend2"]
				require.NotNil(t, backend2Policy)
				require.NotNil(t, backend2Policy.Policy.Spec.GetBackendTls())
				assert.Equal(t, "backend2.example.com", backend2Policy.Policy.Spec.GetBackendTls().Hostname.GetValue())
				assert.NotNil(t, backend2Policy.Policy.Spec.GetBackendTls().Root)
				assert.Nil(t, backend2Policy.Policy.Spec.GetBackendTls().Cert)
				assert.Nil(t, backend2Policy.Policy.Spec.GetBackendTls().Key)
			},
		},
		{
			name: "one TLS policy and two config policies targeting two backends (one without match)",
			tlsPolicies: []*gwv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-policy-backend1",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend1"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "backend1.example.com",
						},
					},
				},
			},
			configPolicies: []*v1alpha1.BackendConfigPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "config-policy-backend1",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendConfigPolicySpec{
						TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend1"),
								},
							},
						},
						TLS: &v1alpha1.TLS{
							SecretRef: &corev1.LocalObjectReference{
								Name: "client-tls-secret",
							},
							Sni: ptr.To("backend1.example.com"),
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "config-policy-backend2",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendConfigPolicySpec{
						TargetRefs: []v1alpha1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: v1alpha1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("backend2"),
								},
							},
						},
						TLS: &v1alpha1.TLS{
							SecretRef: &corev1.LocalObjectReference{
								Name: "client-tls-secret",
							},
							Sni: ptr.To("backend2.example.com"),
						},
					},
				},
			},
			backends: []*v1alpha1.Backend{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend1",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeStatic,
						Static: &v1alpha1.StaticBackend{
							Hosts: []v1alpha1.Host{
								{
									Host: "backend1.example.com",
									Port: 443,
								},
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backend2",
						Namespace: "default",
					},
					Spec: v1alpha1.BackendSpec{
						Type: v1alpha1.BackendTypeStatic,
						Static: &v1alpha1.StaticBackend{
							Hosts: []v1alpha1.Host{
								{
									Host: "backend2.example.com",
									Port: 443,
								},
							},
						},
					},
				},
			},
			configMaps:    []*corev1.ConfigMap{configMap},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 2)

				// Should have one merged policy for backend1 and one config-only policy for backend2
				policyMap := make(map[string]*AgwPolicy)
				for _, policy := range policies {
					policyMap[policy.Policy.Name] = &policy
				}

				backend1Policy := policyMap["merged-tls-policy:backend:default/backend1"]
				require.NotNil(t, backend1Policy)
				require.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls())
				assert.Equal(t, "backend1.example.com", backend1Policy.Policy.Spec.GetBackendTls().Hostname.GetValue())
				assert.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls().Root)
				assert.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls().Cert)
				assert.NotNil(t, backend1Policy.Policy.Spec.GetBackendTls().Key)

				backend2Policy := policyMap["default/config-policy-backend2:backendconfig:default/backend2"]
				require.NotNil(t, backend2Policy)
				require.NotNil(t, backend2Policy.Policy.Spec.GetBackendTls())
				assert.Equal(t, "backend2.example.com", backend2Policy.Policy.Spec.GetBackendTls().Hostname.GetValue())
				assert.Nil(t, backend2Policy.Policy.Spec.GetBackendTls().Root)
				assert.NotNil(t, backend2Policy.Policy.Spec.GetBackendTls().Cert)
				assert.NotNil(t, backend2Policy.Policy.Spec.GetBackendTls().Key)
			},
		},
		{
			name: "multiple TLS policies targeting same backend",
			tlsPolicies: []*gwv1.BackendTLSPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-policy-1",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("test-backend"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "policy1.example.com",
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tls-policy-2",
						Namespace: "default",
					},
					Spec: gwv1.BackendTLSPolicySpec{
						TargetRefs: []gwv1.LocalPolicyTargetReferenceWithSectionName{
							{
								LocalPolicyTargetReference: gwv1.LocalPolicyTargetReference{
									Group: gwv1.Group(wellknown.BackendGVK.Group),
									Kind:  gwv1.Kind(wellknown.BackendGVK.Kind),
									Name:  gwv1.ObjectName("test-backend"),
								},
							},
						},
						Validation: gwv1.BackendTLSPolicyValidation{
							CACertificateRefs: []gwv1.LocalObjectReference{
								{
									Group: gwv1.Group(wellknown.ConfigMapGVK.Group),
									Kind:  gwv1.Kind(wellknown.ConfigMapGVK.Kind),
									Name:  "test-ca-cert",
								},
							},
							Hostname: "policy2.example.com", // Different hostname
						},
					},
				},
			},
			backends:      []*v1alpha1.Backend{backend},
			configMaps:    []*corev1.ConfigMap{configMap},
			secrets:       []*corev1.Secret{secret},
			clusterDomain: "cluster.local",
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				// A single policy should be produced
				require.Len(t, policies, 1)

				policyMap := make(map[string]*AgwPolicy)
				for _, policy := range policies {
					policyMap[policy.Policy.Name] = &policy
				}

				policy1 := policyMap["default/tls-policy-1:backendtls:default/test-backend"]
				require.NotNil(t, policy1)
				require.NotNil(t, policy1.Policy.Spec.GetBackendTls())
				// The first processed policy takes precedence
				assert.Equal(t, "policy1.example.com", policy1.Policy.Spec.GetBackendTls().Hostname.GetValue())
				assert.NotNil(t, policy1.Policy.Spec.GetBackendTls().Root)
				assert.Nil(t, policy1.Policy.Spec.GetBackendTls().Cert)
				assert.Nil(t, policy1.Policy.Spec.GetBackendTls().Key)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create collections for testing
			backendsCol := krt.NewStaticCollection(nil, tt.backends)
			configMapsCol := krt.NewStaticCollection(nil, tt.configMaps)
			secretsCol := krt.NewStaticCollection(nil, tt.secrets)

			// Create TLS policy collection to pass to mergeTLSAndConfigPolicies
			var tlsPolicies []AgwPolicy
			for _, tlsPolicy := range tt.tlsPolicies {
				tlsPolicyResults := translatePoliciesForBackendTLS(krtctx, configMapsCol, backendsCol, tlsPolicy, tt.clusterDomain)
				tlsPolicies = append(tlsPolicies, tlsPolicyResults...)
			}
			tlsPolicyCol := krt.NewStaticCollection(nil, tlsPolicies)

			// Create config policy collection to pass to mergeTLSAndConfigPolicies
			var configPolicies []AgwPolicy
			for _, configPolicy := range tt.configPolicies {
				configPolicyResults := translatePoliciesForBackendConfig(krtctx, backendsCol, secretsCol, configPolicy, tt.clusterDomain)
				configPolicies = append(configPolicies, configPolicyResults...)
			}
			configPolicyCol := krt.NewStaticCollection(nil, configPolicies)

			// Test policy merging
			mergedPolicies := mergeTLSAndConfigPolicies(tlsPolicyCol, configPolicyCol)
			if tt.validate != nil {
				tt.validate(t, mergedPolicies.List(), nil)
			}
		})
	}
}

func TestGetTargetKey(t *testing.T) {
	tests := []struct {
		name     string
		policy   *api.Policy
		expected string
	}{
		{
			name: "backend target",
			policy: &api.Policy{
				Target: &api.PolicyTarget{
					Kind: &api.PolicyTarget_Backend{
						Backend: "default/test-backend",
					},
				},
			},
			expected: "backend:default/test-backend",
		},
		{
			name: "service target",
			policy: &api.Policy{
				Target: &api.PolicyTarget{
					Kind: &api.PolicyTarget_Service{
						Service: "default/test-service",
					},
				},
			},
			expected: "service:default/test-service",
		},
		{
			name: "sub-backend target",
			policy: &api.Policy{
				Target: &api.PolicyTarget{
					Kind: &api.PolicyTarget_SubBackend{
						SubBackend: "default/test-backend/openai-provider",
					},
				},
			},
			expected: "subbackend:default/test-backend/openai-provider",
		},
		{
			name: "nil target",
			policy: &api.Policy{
				Target: nil,
			},
			expected: "",
		},
		{
			name: "nil target kind",
			policy: &api.Policy{
				Target: &api.PolicyTarget{
					Kind: nil,
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTargetKey(tt.policy)
			assert.Equal(t, tt.expected, result)
		})
	}
}
