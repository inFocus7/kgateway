package plugins

import (
	"testing"

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
		{
			name: "BackendConfigPolicy with multiple target refs",
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
			validate: func(t *testing.T, policies []AgwPolicy, err error) {
				require.NoError(t, err)
				require.Len(t, policies, 2)
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
