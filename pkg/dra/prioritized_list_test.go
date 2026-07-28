/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dra

// Tests for count-based FirstAvailable (prioritized alternative) quota: the
// component-wise-max envelope that admits a prioritized-list claim instead of
// rejecting it. The envelope charge is measured against the charge-each-alternative
// sum on the same claims, and the current admission path is confirmed to still
// reject these claims with the gate off. Implements KEP-2941 prioritized-list
// quota; see kubernetes-sigs/kueue#13599.

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	configapi "sigs.k8s.io/kueue/apis/config/v1beta2"
	kueue "sigs.k8s.io/kueue/apis/kueue/v1beta2"
	"sigs.k8s.io/kueue/pkg/features"
	utiltesting "sigs.k8s.io/kueue/pkg/util/testing"
)

type subSpec struct {
	name  string
	class string
	count int64
	mode  resourcev1.DeviceAllocationMode
}

func exactCount(name, class string, count int64) subSpec {
	return subSpec{name: name, class: class, count: count, mode: resourcev1.DeviceAllocationModeExactCount}
}

func faReq(name string, subs ...subSpec) resourcev1.DeviceRequest {
	req := resourcev1.DeviceRequest{Name: name}
	for _, s := range subs {
		req.FirstAvailable = append(req.FirstAvailable, resourcev1.DeviceSubRequest{
			Name:            s.name,
			DeviceClassName: s.class,
			AllocationMode:  s.mode,
			Count:           s.count,
		})
	}
	return req
}

func specOf(reqs ...resourcev1.DeviceRequest) resourcev1.ResourceClaimSpec {
	return resourcev1.ResourceClaimSpec{Devices: resourcev1.DeviceClaim{Requests: reqs}}
}

func rlToInt(rl corev1.ResourceList) map[corev1.ResourceName]int64 {
	out := map[corev1.ResourceName]int64{}
	for n, q := range rl {
		out[n] = q.Value()
	}
	return out
}

func envelopeMapper(t *testing.T) *ResourceMapper {
	t.Helper()
	// gpu-high and gpu-low both map to the single logical "gpu" quota resource;
	// cpu-class maps to "cpu". Same-logical alternatives are where the envelope
	// beats the sum.
	mapper := NewResourceMapper()
	if err := mapper.PopulateFromConfiguration([]configapi.DeviceClassMapping{
		{Name: "gpu", DeviceClassNames: []corev1.ResourceName{"gpu-high", "gpu-low"}},
		{Name: "cpu", DeviceClassNames: []corev1.ResourceName{"cpu-class"}},
	}); err != nil {
		t.Fatalf("populate mapper: %v", err)
	}
	return mapper
}

func Test_firstAvailableCharges_envelopeVsSum(t *testing.T) {
	mapper := envelopeMapper(t)

	tests := []struct {
		name         string
		spec         resourcev1.ResourceClaimSpec
		wantEnvelope map[corev1.ResourceName]int64
		wantSum      map[corev1.ResourceName]int64
		wantErr      bool
	}{
		{
			name:         "same logical resource (prefer-hi-else-lo): envelope is max, sum is total",
			spec:         specOf(faReq("accel", exactCount("hi", "gpu-high", 1), exactCount("lo", "gpu-low", 1))),
			wantEnvelope: map[corev1.ResourceName]int64{"gpu": 1},
			wantSum:      map[corev1.ResourceName]int64{"gpu": 2},
		},
		{
			name:         "disjoint resources (gpu-or-cpu): envelope equals sum (win is over reject, not over sum)",
			spec:         specOf(faReq("accel", exactCount("g", "gpu-high", 1), exactCount("c", "cpu-class", 1))),
			wantEnvelope: map[corev1.ResourceName]int64{"gpu": 1, "cpu": 1},
			wantSum:      map[corev1.ResourceName]int64{"gpu": 1, "cpu": 1},
		},
		{
			name:         "three same-resource alternatives, different counts: max vs total",
			spec:         specOf(faReq("accel", exactCount("a", "gpu-high", 1), exactCount("b", "gpu-low", 2), exactCount("c", "gpu-high", 4))),
			wantEnvelope: map[corev1.ResourceName]int64{"gpu": 4},
			wantSum:      map[corev1.ResourceName]int64{"gpu": 7},
		},
		{
			name: "two independent firstAvailable requests: per-request max, summed across requests",
			spec: specOf(
				faReq("r1", exactCount("hi", "gpu-high", 1), exactCount("lo", "gpu-low", 1)),
				faReq("r2", exactCount("hi", "gpu-high", 2), exactCount("lo", "gpu-low", 3)),
			),
			wantEnvelope: map[corev1.ResourceName]int64{"gpu": 4}, // max(1,1)=1 + max(2,3)=3
			wantSum:      map[corev1.ResourceName]int64{"gpu": 7}, // (1+1) + (2+3)
		},
		{
			name:    "unbounded (AllocationMode All) subrequest is rejected",
			spec:    specOf(faReq("accel", exactCount("g", "gpu-high", 1), subSpec{name: "all", class: "gpu-low", mode: resourcev1.DeviceAllocationModeAll})),
			wantErr: true,
		},
		{
			name:    "unmapped DeviceClass is rejected",
			spec:    specOf(faReq("accel", exactCount("x", "unmapped-class", 1))),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := tc.spec
			env, sum, errs := firstAvailableCharges(&spec, mapper, field.NewPath("spec"))

			if tc.wantErr {
				if len(errs) == 0 {
					t.Fatalf("expected a field error, got none (env=%v sum=%v)", rlToInt(env), rlToInt(sum))
				}
				return
			}
			if len(errs) > 0 {
				t.Fatalf("unexpected field errors: %v", errs)
			}

			gotEnv, gotSum := rlToInt(env), rlToInt(sum)
			if diff := cmp.Diff(tc.wantEnvelope, gotEnv); diff != "" {
				t.Errorf("envelope charge mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantSum, gotSum); diff != "" {
				t.Errorf("sum charge mismatch (-want +got):\n%s", diff)
			}

			// Safety/tightness: the envelope must never be looser than KEP-4816's
			// sum on any resource, and we surface how much tighter it is.
			for res, e := range gotEnv {
				s := gotSum[res]
				if e > s {
					t.Errorf("envelope[%s]=%d exceeds sum[%s]=%d; envelope must be <= sum component-wise", res, e, res, s)
				}
				if s > 0 {
					t.Logf("resource %q: envelope=%d sum=%d (envelope reserves %.0f%% of the KEP-4816 sum)", res, e, s, 100*float64(e)/float64(s))
				}
			}
		})
	}
}

func psMapToInt(m map[kueue.PodSetReference]corev1.ResourceList) map[kueue.PodSetReference]map[corev1.ResourceName]int64 {
	out := map[kueue.PodSetReference]map[corev1.ResourceName]int64{}
	for ps, rl := range m {
		out[ps] = rlToInt(rl)
	}
	return out
}

// Test_GetResourceRequests_FirstAvailableEnvelopeEndToEnd drives the real
// admission path (GetResourceRequestsForResourceClaimTemplates) for a Workload
// whose ResourceClaimTemplate uses a FirstAvailable prioritized list. With the
// KueueDRAIntegrationPrioritizedList gate OFF the path rejects the claim (status
// quo); with the gate ON the claim is admitted and charged the component-wise-max
// envelope (prefer-gpu-high-else-gpu-low, both -> one gpu, envelope gpu:1).
func Test_GetResourceRequests_FirstAvailableEnvelopeEndToEnd(t *testing.T) {
	tmplName := "fa-tmpl"
	tmpl := &resourcev1.ResourceClaimTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: tmplName, Namespace: "ns1"},
		Spec: resourcev1.ResourceClaimTemplateSpec{
			Spec: specOf(faReq("accel",
				exactCount("hi", "gpu-high", 1),
				exactCount("lo", "gpu-low", 1))),
		},
	}
	wl := &kueue.Workload{
		ObjectMeta: metav1.ObjectMeta{Name: "wl", Namespace: "ns1"},
		Spec: kueue.WorkloadSpec{
			PodSets: []kueue.PodSet{{
				Name:  "main",
				Count: 1,
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "c", Image: "pause"}},
						ResourceClaims: []corev1.PodResourceClaim{
							{Name: "req", ResourceClaimTemplateName: &tmplName},
						},
					},
				},
			}},
		},
	}

	mapper := envelopeMapper(t)
	cl := utiltesting.NewClientBuilder().WithObjects(tmpl).Build()
	sliceCache := NewResourceSliceCache(cl)
	ctx, _ := utiltesting.ContextWithLog(t)

	t.Run("gate off: FirstAvailable rejected (status quo)", func(t *testing.T) {
		_, errs := GetResourceRequestsForResourceClaimTemplates(ctx, cl, sliceCache, mapper, wl)
		if len(errs) == 0 {
			t.Fatalf("expected rejection with the gate off, got none")
		}
		t.Logf("gate off rejects: %v", errs[0])
	})

	t.Run("gate on: admitted with envelope charge gpu:1", func(t *testing.T) {
		features.SetFeatureGateDuringTest(t, features.KueueDRAIntegrationPrioritizedList, true)
		got, errs := GetResourceRequestsForResourceClaimTemplates(ctx, cl, sliceCache, mapper, wl)
		if len(errs) > 0 {
			t.Fatalf("unexpected error with gate on: %v", errs)
		}
		want := map[kueue.PodSetReference]map[corev1.ResourceName]int64{
			"main": {"gpu": 1},
		}
		if diff := cmp.Diff(want, psMapToInt(got)); diff != "" {
			t.Errorf("admitted charge mismatch (-want +got):\n%s", diff)
		}
	})
}

// Test_GetResourceRequests_MixedExactlyAndFirstAvailable hardens the no-double-count
// property: a claim with BOTH an exactly request and a FirstAvailable request must
// charge their sum (exactly gpu:1 + envelope max over alternatives gpu:1 = gpu:2),
// since countDevicesPerClass handles the exactly request and firstAvailableCharges
// handles the FirstAvailable one over disjoint request sets.
func Test_GetResourceRequests_MixedExactlyAndFirstAvailable(t *testing.T) {
	features.SetFeatureGateDuringTest(t, features.KueueDRAIntegrationPrioritizedList, true)

	tmplName := "mixed-tmpl"
	exactReq := resourcev1.DeviceRequest{
		Name: "fixed",
		Exactly: &resourcev1.ExactDeviceRequest{
			DeviceClassName: "gpu-high",
			AllocationMode:  resourcev1.DeviceAllocationModeExactCount,
			Count:           1,
		},
	}
	tmpl := &resourcev1.ResourceClaimTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: tmplName, Namespace: "ns1"},
		Spec: resourcev1.ResourceClaimTemplateSpec{
			Spec: specOf(exactReq, faReq("accel", exactCount("hi", "gpu-high", 1), exactCount("lo", "gpu-low", 1))),
		},
	}
	wl := &kueue.Workload{
		ObjectMeta: metav1.ObjectMeta{Name: "wl", Namespace: "ns1"},
		Spec: kueue.WorkloadSpec{
			PodSets: []kueue.PodSet{{
				Name:  "main",
				Count: 1,
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers:     []corev1.Container{{Name: "c", Image: "pause"}},
						ResourceClaims: []corev1.PodResourceClaim{{Name: "req", ResourceClaimTemplateName: &tmplName}},
					},
				},
			}},
		},
	}

	cl := utiltesting.NewClientBuilder().WithObjects(tmpl).Build()
	sliceCache := NewResourceSliceCache(cl)
	ctx, _ := utiltesting.ContextWithLog(t)

	got, errs := GetResourceRequestsForResourceClaimTemplates(ctx, cl, sliceCache, envelopeMapper(t), wl)
	if len(errs) > 0 {
		t.Fatalf("unexpected error: %v", errs)
	}
	want := map[kueue.PodSetReference]map[corev1.ResourceName]int64{"main": {"gpu": 2}}
	if diff := cmp.Diff(want, psMapToInt(got)); diff != "" {
		t.Errorf("mixed charge mismatch (-want +got):\n%s", diff)
	}
}

// Test_firstAvailableCharges_rejectsSourceBacked verifies the initial-scope guard:
// a firstAvailable alternative over a counter-backed (or capacity-backed) DeviceClass
// is rejected rather than charged, since those accounting paths handle only Exactly.
func Test_firstAvailableCharges_rejectsSourceBacked(t *testing.T) {
	mapper := NewResourceMapper()
	if err := mapper.PopulateFromConfiguration([]configapi.DeviceClassMapping{
		{
			Name:             "gpu-mem",
			DeviceClassNames: []corev1.ResourceName{"mig-class"},
			Sources: []configapi.DeviceClassSourceConfig{
				{Counter: &configapi.DeviceClassCounterSource{Name: "memory", Driver: "gpu.nvidia.com"}},
			},
		},
	}); err != nil {
		t.Fatalf("populate mapper: %v", err)
	}

	spec := specOf(faReq("accel", exactCount("mig", "mig-class", 1)))
	_, _, errs := firstAvailableCharges(&spec, mapper, field.NewPath("spec"))
	if len(errs) == 0 {
		t.Fatalf("expected a counter-backed firstAvailable alternative to be rejected, got none")
	}
	t.Logf("counter-backed alternative rejected: %v", errs[0])
}

// Test_countDevicesPerClass_stillRejectsFirstAvailable documents the status quo:
// the SAME prioritized claim that firstAvailableCharges would admit with a bounded
// envelope is rejected outright by the current admission path.
func Test_countDevicesPerClass_stillRejectsFirstAvailable(t *testing.T) {
	spec := specOf(faReq("accel", exactCount("hi", "gpu-high", 1), exactCount("lo", "gpu-low", 1)))
	_, errs := countDevicesPerClass(&spec)
	if len(errs) == 0 {
		t.Fatalf("expected the current path to reject FirstAvailable, but it did not")
	}
	t.Logf("current admission path rejects the same claim: %v", errs[0])
}
