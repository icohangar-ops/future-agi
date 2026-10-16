package approval

import (
	"context"
	"testing"
	"time"

	"github.com/futureagi/agentcc-gateway/internal/config"
	"github.com/futureagi/agentcc-gateway/internal/guardrails"
	"github.com/futureagi/agentcc-gateway/internal/guardrails/policy"
	"github.com/futureagi/agentcc-gateway/internal/models"
	"github.com/futureagi/agentcc-gateway/internal/pipeline"
	"github.com/futureagi/agentcc-gateway/internal/tenant"
)

func paymentConfig() map[string]interface{} {
	return map[string]interface{}{
		"provider":     "approval",
		"max_amount":   1000.0,
		"environments": []interface{}{"prod", "production"},
		"destructive":  true,
		"rules": []interface{}{
			map[string]interface{}{
				"tool":     "send_payment",
				"argument": "vendor",
				"equals":   "shadow-llc",
				"verdict":  "deny",
			},
		},
	}
}

func responseWith(name, args string) *guardrails.CheckInput {
	return &guardrails.CheckInput{
		Response: &models.ChatCompletionResponse{
			Choices: []models.Choice{{
				Message: models.Message{
					Role: "assistant",
					ToolCalls: []models.ToolCall{{
						ID:   "call_1",
						Type: "function",
						Function: models.FunctionCall{
							Name:      name,
							Arguments: args,
						},
					}},
				},
			}},
		},
	}
}

func TestIsApprovalConfig(t *testing.T) {
	if !IsApprovalConfig(map[string]interface{}{"provider": "approval"}) {
		t.Fatal("approval provider")
	}
	if !IsApprovalConfig(map[string]interface{}{"provider": "argument_approval"}) {
		t.Fatal("argument_approval provider")
	}
	if IsApprovalConfig(map[string]interface{}{"provider": "tool_permission"}) {
		t.Fatal("tool permission is not an approval check")
	}
}

func TestSpendOverCapEscalates(t *testing.T) {
	g := New("payment-approval", paymentConfig())
	result := g.Check(context.Background(), responseWith("send_payment", `{"amount":1500,"vendor":"northwind"}`))
	if result.Pass {
		t.Fatal("expected escalate")
	}
	if result.Action != guardrails.ActionEscalate {
		t.Fatalf("action = %v, want escalate", result.Action)
	}
	if result.Details["verdict"] != "escalate" {
		t.Fatalf("verdict = %v", result.Details["verdict"])
	}
}

func TestSpendUnderCapPasses(t *testing.T) {
	g := New("payment-approval", paymentConfig())
	result := g.Check(context.Background(), responseWith("send_payment", `{"amount":40,"vendor":"northwind","environment":"dev"}`))
	if !result.Pass {
		t.Fatalf("expected pass, got %s", result.Message)
	}
}

func TestProdEnvironmentEscalates(t *testing.T) {
	g := New("payment-approval", paymentConfig())
	result := g.Check(context.Background(), responseWith("send_payment", `{"amount":40,"environment":"prod"}`))
	if result.Pass || result.Details["verdict"] != "escalate" {
		t.Fatalf("prod call should escalate, got pass=%v message=%s", result.Pass, result.Message)
	}
}

func TestDestructiveVerbEscalates(t *testing.T) {
	g := New("payment-approval", paymentConfig())
	result := g.Check(context.Background(), responseWith("delete_invoice", `{"invoice_id":"INV-1"}`))
	if result.Pass || result.Details["verdict"] != "escalate" {
		t.Fatal("delete_invoice should escalate")
	}
	// "format" contains no destructive token, even though it contains the letters of none of the verbs as a token.
	safe := g.Check(context.Background(), responseWith("format_report", `{"command":"format the monthly report"}`))
	if !safe.Pass {
		t.Fatalf("format_report should pass, got %s", safe.Message)
	}
}

func TestUnapprovedVendorDenies(t *testing.T) {
	g := New("payment-approval", paymentConfig())
	result := g.Check(context.Background(), responseWith("send_payment", `{"amount":40,"vendor":"shadow-llc"}`))
	if result.Pass {
		t.Fatal("expected deny")
	}
	if result.Action != guardrails.ActionBlock || result.Details["verdict"] != "deny" {
		t.Fatalf("want deny/block, got action=%v verdict=%v", result.Action, result.Details["verdict"])
	}
}

func TestAnsweredRequestCallIsNotPending(t *testing.T) {
	g := New("payment-approval", paymentConfig())
	input := &guardrails.CheckInput{
		Request: &models.ChatCompletionRequest{
			Messages: []models.Message{
				{
					Role: "assistant",
					ToolCalls: []models.ToolCall{{
						ID:       "call_done",
						Type:     "function",
						Function: models.FunctionCall{Name: "delete_invoice", Arguments: `{"invoice_id":"INV-1"}`},
					}},
				},
				{Role: "tool", ToolCallID: "call_done", Content: []byte(`"ok"`)},
				{Role: "user", Content: []byte(`"thanks"`)},
			},
		},
	}
	result := g.Check(context.Background(), input)
	if !result.Pass {
		t.Fatalf("a tool call that already has a result is history, got %s", result.Message)
	}
}

func TestPendingRequestCallEscalates(t *testing.T) {
	g := New("payment-approval", paymentConfig())
	input := &guardrails.CheckInput{
		Request: &models.ChatCompletionRequest{
			Messages: []models.Message{{
				Role: "assistant",
				ToolCalls: []models.ToolCall{{
					ID:       "call_open",
					Type:     "function",
					Function: models.FunctionCall{Name: "send_payment", Arguments: `{"amount":5000,"vendor":"northwind"}`},
				}},
			}},
		},
	}
	result := g.Check(context.Background(), input)
	if result.Pass || result.Details["verdict"] != "escalate" {
		t.Fatal("pending over-cap call should escalate before the provider")
	}
}

func approvalFactory(name string, cfg map[string]interface{}) guardrails.Guardrail {
	if IsApprovalConfig(cfg) {
		return New(name, cfg)
	}
	return nil
}

func orgApprovalPlugin(action string) *guardrails.GuardrailPlugin {
	store := tenant.NewStore()
	check := &tenant.GuardrailCheck{
		Enabled:             true,
		Action:              action,
		ConfidenceThreshold: 0.5,
		Config:              paymentConfig(),
	}
	store.Set("org-pay", &tenant.OrgConfig{
		Guardrails: &tenant.GuardrailConfig{
			Checks: map[string]*tenant.GuardrailCheck{
				"payment-approval": check,
			},
		},
	})
	return guardrails.NewPlugin(nil, map[string]guardrails.Guardrail{}, approvalFactory, nil, store)
}

func TestOrgApproval_HoldsSpendOverCap(t *testing.T) {
	plugin := orgApprovalPlugin("block")
	rc := models.AcquireRequestContext()
	rc.Metadata["org_id"] = "org-pay"
	rc.Response = responseWith("send_payment", `{"amount":1500,"vendor":"northwind"}`).Response

	result := plugin.ProcessResponse(context.Background(), rc)
	if result.Action != pipeline.ShortCircuit || result.Error == nil {
		t.Fatalf("result = %+v, want approval error", result)
	}
	if result.Error.Code != "approval_required" {
		t.Fatalf("code = %q, want approval_required", result.Error.Code)
	}
	if rc.Response != nil {
		t.Fatal("held tool call should be cleared from the response")
	}
	if rc.Metadata["guardrail_action"] != "escalate" {
		t.Fatalf("guardrail_action = %q", rc.Metadata["guardrail_action"])
	}
	if rc.Metadata["approval_required"] != "true" {
		t.Fatalf("approval_required = %q", rc.Metadata["approval_required"])
	}
}

func TestOrgApproval_DeniesUnapprovedVendor(t *testing.T) {
	plugin := orgApprovalPlugin("block")
	rc := models.AcquireRequestContext()
	rc.Metadata["org_id"] = "org-pay"
	rc.Response = responseWith("send_payment", `{"amount":40,"vendor":"shadow-llc"}`).Response

	result := plugin.ProcessResponse(context.Background(), rc)
	if result.Error == nil || result.Error.Code != "content_blocked" {
		t.Fatalf("code = %v, want content_blocked", result.Error)
	}
	if rc.Metadata["guardrail_action"] != "blocked" {
		t.Fatalf("guardrail_action = %q", rc.Metadata["guardrail_action"])
	}
}

func TestOrgApproval_AllowsSpendUnderCap(t *testing.T) {
	plugin := orgApprovalPlugin("block")
	rc := models.AcquireRequestContext()
	rc.Metadata["org_id"] = "org-pay"
	rc.Response = responseWith("send_payment", `{"amount":40,"vendor":"northwind","environment":"dev"}`).Response

	result := plugin.ProcessResponse(context.Background(), rc)
	if result.Action != pipeline.Continue {
		t.Fatalf("result = %+v, want continue", result)
	}
	if rc.Response == nil {
		t.Fatal("allowed tool call should stay on the response")
	}
}

func TestOrgApproval_LogActionDoesNotHold(t *testing.T) {
	plugin := orgApprovalPlugin("log")
	rc := models.AcquireRequestContext()
	rc.Metadata["org_id"] = "org-pay"
	rc.Response = responseWith("send_payment", `{"amount":1500,"vendor":"northwind"}`).Response

	result := plugin.ProcessResponse(context.Background(), rc)
	if result.Action != pipeline.Continue {
		t.Fatalf("log action should not hold the call, got %+v", result)
	}
	if rc.Metadata["guardrail_action"] != "logged" {
		t.Fatalf("guardrail_action = %q", rc.Metadata["guardrail_action"])
	}
	if rc.Response == nil {
		t.Fatal("log action should leave the tool call in place")
	}
}

func TestOrgApproval_HoldsPendingRequestCall(t *testing.T) {
	plugin := orgApprovalPlugin("escalate")
	rc := models.AcquireRequestContext()
	rc.Metadata["org_id"] = "org-pay"
	rc.Request = &models.ChatCompletionRequest{
		Model: "gpt-4o",
		Messages: []models.Message{{
			Role: "assistant",
			ToolCalls: []models.ToolCall{{
				ID:   "call_pending",
				Type: "function",
				Function: models.FunctionCall{
					Name:      "delete_invoice",
					Arguments: `{"invoice_id":"inv-9"}`,
				},
			}},
		}},
	}

	result := plugin.ProcessRequest(context.Background(), rc)
	if result.Error == nil || result.Error.Code != "approval_required" {
		t.Fatalf("code = %v, want approval_required", result.Error)
	}
}

func TestEngineBothStages_HoldsModelToolCall(t *testing.T) {
	name := "payment-approval"
	registry := map[string]guardrails.Guardrail{
		name: New(name, paymentConfig()),
	}
	cfg := config.GuardrailsConfig{
		Enabled:        true,
		DefaultTimeout: 5 * time.Second,
		Rules: []config.GuardrailRuleConfig{{
			Name:      name,
			Stage:     "both",
			Mode:      "sync",
			Action:    "block",
			Threshold: 0.5,
		}},
	}
	engine := guardrails.NewEngine(cfg, registry)
	if engine.PreCount() != 1 || engine.PostCount() != 1 {
		t.Fatalf("pre=%d post=%d, want both stages", engine.PreCount(), engine.PostCount())
	}

	input := &guardrails.CheckInput{
		Response: responseWith("deploy", `{"environment":"prod"}`).Response,
		Metadata: map[string]string{},
	}
	result := engine.RunPost(context.Background(), input, nil, policy.RequestPolicyNone)
	if !result.Escalated {
		t.Fatalf("expected escalate, triggered=%v blocked=%v", result.Triggered, result.Blocked)
	}
	if result.Blocked {
		t.Fatal("escalate should not be recorded as a block")
	}
}
