// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

//go:build e2e

package tests

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwhttp "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"

	"github.com/envoyproxy/gateway/internal/gatewayapi"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
)

// testOIDCWithAuthorizationDeny verifies that authentication-independent
// authorization deny rules are enforced before the OIDC filter on the same
// route. Covers both clientCIDRs (on the shared conformance Gateway) and
// clientIPGeoLocations (on a GeoIP-enabled Gateway). A denied client must
// receive a 403, not a 302 redirect to the identity provider, while an allowed
// client is still redirected to the IdP. See
// https://github.com/envoyproxy/gateway/issues/8913.
//
// Invoked from OIDCTest so it can reuse the already-running Keycloak instance.
func testOIDCWithAuthorizationDeny(t *testing.T, suite *suite.ConformanceTestSuite) {
	t.Run("CIDR authorization deny is enforced before the OIDC redirect (#8913)", func(t *testing.T) {
		const ns = "gateway-conformance-infra"

		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, "testdata/oidc-authorization.yaml", true)

		routeNN := types.NamespacedName{Name: "http-with-oidc-authz", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		ancestorRef := gwapiv1.ParentReference{
			Group:     gatewayapi.GroupPtr(gwapiv1.GroupName),
			Kind:      gatewayapi.KindPtr(resource.KindGateway),
			Namespace: gatewayapi.NamespacePtr(gwNN.Namespace),
			Name:      gwapiv1.ObjectName(gwNN.Name),
		}
		SecurityPolicyMustBeAccepted(t, suite.Client, types.NamespacedName{Name: "oidc-authz", Namespace: ns}, suite.ControllerName, ancestorRef)
		ClientTrafficPolicyMustBeAccepted(t, suite.Client, types.NamespacedName{Name: "oidc-authz-client-ip-detection", Namespace: ns}, suite.ControllerName, ancestorRef)

		// A client in the denied CIDR must be rejected with 403 before the OIDC
		// filter runs. Before the fix this returned a 302 redirect to Keycloak.
		t.Run("denied client gets 403 instead of an OIDC redirect", func(t *testing.T) {
			expectedResponse := gwhttp.ExpectedResponse{
				Request: gwhttp.Request{
					Host:             "www.example.com",
					Path:             "/protected-oidc",
					UnfollowRedirect: true,
					Headers: map[string]string{
						"X-Forwarded-For": "192.168.1.1", // in the denied CIDR
					},
				},
				Response: gwhttp.Response{
					StatusCodes: []int{403},
				},
				Namespace: ns,
			}
			gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, expectedResponse)
		})

		// A client outside the denied CIDR is not short-circuited by the deny and
		// is redirected to the identity provider by the OIDC filter, confirming
		// OIDC still applies after the pre-auth authorization stage.
		t.Run("allowed client is still redirected to the IdP", func(t *testing.T) {
			expectedResponse := gwhttp.ExpectedResponse{
				Request: gwhttp.Request{
					Host:             "www.example.com",
					Path:             "/protected-oidc",
					UnfollowRedirect: true,
					Headers: map[string]string{
						"X-Forwarded-For": "192.168.3.1", // outside the denied CIDR
					},
				},
				Response: gwhttp.Response{
					StatusCodes: []int{302},
				},
				Namespace: ns,
			}
			gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, expectedResponse)
		})
	})

	t.Run("geo authorization deny is enforced before the OIDC redirect (#8913)", func(t *testing.T) {
		const ns = "gateway-conformance-infra"

		// MaxMind test DB ConfigMap lives in authorization-geoip-country.yaml.
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, "testdata/authorization-geoip-country.yaml", true)
		ensureGeoIPConfigMap(t, suite)
		suite.Applier.MustApplyWithCleanup(t, suite.Client, suite.TimeoutConfig, "testdata/oidc-authorization-geoip.yaml", true)

		routeNN := types.NamespacedName{Name: "http-with-oidc-geo-authz", Namespace: ns}
		gwNN := types.NamespacedName{Name: "oidc-geoip-authz-gateway", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		ancestorRef := gwapiv1.ParentReference{
			Group:     gatewayapi.GroupPtr(gwapiv1.GroupName),
			Kind:      gatewayapi.KindPtr(resource.KindGateway),
			Namespace: gatewayapi.NamespacePtr(gwNN.Namespace),
			Name:      gwapiv1.ObjectName(gwNN.Name),
		}
		SecurityPolicyMustBeAccepted(t, suite.Client, types.NamespacedName{Name: "oidc-geo-authz", Namespace: ns}, suite.ControllerName, ancestorRef)
		ClientTrafficPolicyMustBeAccepted(t, suite.Client, types.NamespacedName{Name: "oidc-geo-authz-client-ip-detection", Namespace: ns}, suite.ControllerName, ancestorRef)

		// A client in the denied country must get 403 before OIDC runs.
		t.Run("denied country gets 403 instead of an OIDC redirect", func(t *testing.T) {
			expectedResponse := gwhttp.ExpectedResponse{
				Request: gwhttp.Request{
					Host:             "www.example.com",
					Path:             "/protected-oidc-geo",
					UnfollowRedirect: true,
					Headers: map[string]string{
						"X-Forwarded-For": "81.2.69.160", // GeoIP2-Country-Test.mmdb => GB
					},
				},
				Response: gwhttp.Response{
					StatusCodes: []int{403},
				},
				Namespace: ns,
			}
			gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, expectedResponse)
		})

		// A client outside the denied country still hits the OIDC redirect.
		t.Run("allowed country is still redirected to the IdP", func(t *testing.T) {
			expectedResponse := gwhttp.ExpectedResponse{
				Request: gwhttp.Request{
					Host:             "www.example.com",
					Path:             "/protected-oidc-geo",
					UnfollowRedirect: true,
					Headers: map[string]string{
						"X-Forwarded-For": "50.114.0.1", // GeoIP2-Country-Test.mmdb => US
					},
				},
				Response: gwhttp.Response{
					StatusCodes: []int{302},
				},
				Namespace: ns,
			}
			gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, expectedResponse)
		})
	})
}
