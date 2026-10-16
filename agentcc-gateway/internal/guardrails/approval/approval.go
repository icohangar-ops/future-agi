// Package approval holds a tool call for a person when its arguments are
// dangerous. Allow and deny stay with the toolperm guardrail. This one adds
// an escalate verdict: the call is not executed, and the client receives
// approval_required.
//
// Three built-in checks, all off until configured:
//   - environments: escalate when an env/environment/stage argument matches
//   - destructive: escalate when the tool name or an action argument is a
//     destructive verb (delete, drop, rm, ...)
//   - max_amount: escalate when an amount/spend/total argument is over the cap
//
// Optional rules add equals, contains, or greater_than checks, each with a
// verdict of escalate (the default) or deny.
package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/futureagi/agentcc-gateway/internal/guardrails"
	"github.com/futureagi/agentcc-gateway/internal/models"
)

// defaultDestructive are matched as whole tokens, so "format" does not match "rm".
var defaultDestructive = []string{"delete", "drop", "truncate", "destroy", "purge", "wipe", "rm"}

var environmentKeys = []string{"environment", "env", "target_env", "stage"}
var amountKeys = []string{"amount", "spend", "total", "cost", "payment_amount"}
var actionKeys = []string{"action", "command", "operation", "method", "verb", "sql"}

// Guardrail inspects tool-call arguments and returns allow, deny, or escalate.
type Guardrail struct {
	name         string
	environments map[string]struct{}
	destructive  bool
	verbs        []string
	maxAmount    float64
	hasMax       bool
	rules        []rule
}

type rule struct {
	tool        string
	argument    string
	equals      string
	hasEquals   bool
	contains    string
	greaterThan float64
	hasGreater  bool
	verdict     string
}

type match struct {
	tool    string
	verdict string
	reason  string
}

// New builds a guardrail from an org check or a config.yaml rule.
func New(name string, cfg map[string]interface{}) *Guardrail {
	g := &Guardrail{
		name:         name,
		environments: map[string]struct{}{},
		verbs:        append([]string(nil), defaultDestructive...),
	}
	if cfg == nil {
		return g
	}
	for _, env := range stringList(cfg["environments"]) {
		g.environments[strings.ToLower(env)] = struct{}{}
	}
	if v, ok := cfg["destructive"].(bool); ok {
		g.destructive = v
	}
	if verbs := stringList(cfg["destructive_verbs"]); len(verbs) > 0 {
		g.verbs = verbs
		g.destructive = true
	}
	if amount, ok := floatValue(cfg["max_amount"]); ok && amount > 0 {
		g.maxAmount = amount
		g.hasMax = true
	}
	g.rules = parseRules(cfg["rules"])
	return g
}

// IsApprovalConfig reports whether cfg selects this guardrail.
func IsApprovalConfig(cfg map[string]interface{}) bool {
	if cfg == nil {
		return false
	}
	provider, _ := cfg["provider"].(string)
	switch provider {
	case "approval", "argument_approval":
		return true
	default:
		return false
	}
}

func (g *Guardrail) Name() string { return g.name }

// Stage is the model's tool call. Stages also lists the request, so a call
// that is already pending is held before the provider sees it.
func (g *Guardrail) Stage() guardrails.Stage { return guardrails.StagePost }

func (g *Guardrail) Stages() []guardrails.Stage {
	return []guardrails.Stage{guardrails.StagePre, guardrails.StagePost}
}

// Check inspects pending tool calls. A response is the model's new call.
// A request is only the calls that do not yet have a tool result.
func (g *Guardrail) Check(_ context.Context, input *guardrails.CheckInput) *guardrails.CheckResult {
	if input == nil {
		return &guardrails.CheckResult{Pass: true}
	}
	var calls []models.ToolCall
	if input.Response != nil {
		calls = responseCalls(input.Response)
	} else if input.Request != nil {
		calls = pendingCalls(input.Request)
	}
	if len(calls) == 0 {
		return &guardrails.CheckResult{Pass: true}
	}

	var hits []match
	for _, call := range calls {
		hits = append(hits, g.evaluate(call)...)
	}
	if len(hits) == 0 {
		return &guardrails.CheckResult{Pass: true, Score: 0, Message: "tool call arguments permitted"}
	}

	verdict := "escalate"
	action := guardrails.ActionEscalate
	for _, hit := range hits {
		if hit.verdict == "deny" {
			verdict = "deny"
			action = guardrails.ActionBlock
			break
		}
	}
	reasons := make([]string, len(hits))
	details := make([]map[string]string, len(hits))
	for i, hit := range hits {
		reasons[i] = hit.tool + ": " + hit.reason
		details[i] = map[string]string{"tool": hit.tool, "verdict": hit.verdict, "reason": hit.reason}
	}
	return &guardrails.CheckResult{
		Pass:    false,
		Score:   1,
		Action:  action,
		Message: strings.Join(reasons, "; "),
		Details: map[string]interface{}{
			"verdict": verdict,
			"matches": details,
		},
	}
}

func (g *Guardrail) evaluate(call models.ToolCall) []match {
	name := call.Function.Name
	args := parseArgs(call.Function.Arguments)
	var hits []match

	if g.destructive && (tokenHasVerb(name, g.verbs) || argsHaveVerb(args, g.verbs)) {
		hits = append(hits, match{tool: name, verdict: "escalate", reason: "destructive action"})
	}
	if len(g.environments) > 0 {
		if env, ok := argString(args, environmentKeys); ok {
			if _, listed := g.environments[strings.ToLower(env)]; listed {
				hits = append(hits, match{tool: name, verdict: "escalate", reason: "environment " + env})
			}
		}
	}
	if g.hasMax {
		if amount, ok := argNumber(args, amountKeys); ok && amount > g.maxAmount {
			hits = append(hits, match{
				tool:    name,
				verdict: "escalate",
				reason:  fmt.Sprintf("amount %v exceeds cap %v", amount, g.maxAmount),
			})
		}
	}
	for _, rule := range g.rules {
		if !toolMatches(rule.tool, name) {
			continue
		}
		if reason, ok := rule.matches(args); ok {
			hits = append(hits, match{tool: name, verdict: rule.verdict, reason: reason})
		}
	}
	return hits
}

func (r rule) matches(args map[string]interface{}) (string, bool) {
	value, ok := args[r.argument]
	if !ok {
		return "", false
	}
	if r.hasEquals && strings.EqualFold(fmt.Sprint(value), r.equals) {
		return fmt.Sprintf("%s is %s", r.argument, r.equals), true
	}
	if r.contains != "" && strings.Contains(strings.ToLower(fmt.Sprint(value)), strings.ToLower(r.contains)) {
		return fmt.Sprintf("%s contains %s", r.argument, r.contains), true
	}
	if r.hasGreater {
		if number, ok := floatValue(value); ok && number > r.greaterThan {
			return fmt.Sprintf("%s %v exceeds %v", r.argument, number, r.greaterThan), true
		}
	}
	return "", false
}

func parseRules(raw interface{}) []rule {
	items, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var rules []rule
	for _, item := range items {
		fields, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		verdict := "escalate"
		if v, ok := fields["verdict"].(string); ok && (v == "deny" || v == "block") {
			verdict = "deny"
		}
		next := rule{
			tool:     stringOr(fields["tool"], "*"),
			argument: stringOr(fields["argument"], ""),
			verdict:  verdict,
		}
		if eq, ok := fields["equals"].(string); ok {
			next.equals = eq
			next.hasEquals = true
		}
		if contains, ok := fields["contains"].(string); ok {
			next.contains = contains
		}
		if greater, ok := floatValue(fields["greater_than"]); ok {
			next.greaterThan = greater
			next.hasGreater = true
		}
		if next.argument == "" {
			continue
		}
		rules = append(rules, next)
	}
	return rules
}

func toolMatches(pattern, name string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if pattern == name {
		return true
	}
	matched, err := filepath.Match(pattern, name)
	return err == nil && matched
}

func pendingCalls(req *models.ChatCompletionRequest) []models.ToolCall {
	answered := map[string]bool{}
	for _, msg := range req.Messages {
		if msg.Role == "tool" && msg.ToolCallID != "" {
			answered[msg.ToolCallID] = true
		}
	}
	var pending []models.ToolCall
	for _, msg := range req.Messages {
		if msg.Role != "assistant" {
			continue
		}
		for _, call := range msg.ToolCalls {
			if call.ID != "" && answered[call.ID] {
				continue
			}
			pending = append(pending, call)
		}
	}
	return pending
}

func responseCalls(resp *models.ChatCompletionResponse) []models.ToolCall {
	var calls []models.ToolCall
	for _, choice := range resp.Choices {
		calls = append(calls, choice.Message.ToolCalls...)
	}
	return calls
}

func parseArgs(raw string) map[string]interface{} {
	if strings.TrimSpace(raw) == "" {
		return map[string]interface{}{}
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil || parsed == nil {
		return map[string]interface{}{}
	}
	return parsed
}

func argsHaveVerb(args map[string]interface{}, verbs []string) bool {
	for _, key := range actionKeys {
		value, ok := args[key]
		if !ok {
			continue
		}
		if tokenHasVerb(fmt.Sprint(value), verbs) {
			return true
		}
	}
	return false
}

func argString(args map[string]interface{}, keys []string) (string, bool) {
	for _, key := range keys {
		value, ok := args[key]
		if !ok {
			continue
		}
		text := strings.TrimSpace(fmt.Sprint(value))
		if text != "" {
			return text, true
		}
	}
	return "", false
}

func argNumber(args map[string]interface{}, keys []string) (float64, bool) {
	for _, key := range keys {
		value, ok := args[key]
		if !ok {
			continue
		}
		if number, ok := floatValue(value); ok {
			return number, true
		}
	}
	return 0, false
}

func tokenHasVerb(text string, verbs []string) bool {
	folded := strings.ToLower(text)
	for _, verb := range verbs {
		verb = strings.ToLower(strings.TrimSpace(verb))
		if verb == "" {
			continue
		}
		if hasToken(folded, verb) {
			return true
		}
	}
	return false
}

func hasToken(text, verb string) bool {
	start := 0
	for start <= len(text)-len(verb) {
		idx := strings.Index(text[start:], verb)
		if idx < 0 {
			return false
		}
		idx += start
		beforeOK := idx == 0 || !unicode.IsLetter(rune(text[idx-1]))
		end := idx + len(verb)
		afterOK := end == len(text) || !unicode.IsLetter(rune(text[end]))
		if beforeOK && afterOK {
			return true
		}
		start = idx + 1
	}
	return false
}

func stringList(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		var out []string
		for _, part := range strings.Split(v, ",") {
			if text := strings.TrimSpace(part); text != "" {
				out = append(out, text)
			}
		}
		return out
	case []interface{}:
		var out []string
		for _, item := range v {
			if text := strings.TrimSpace(fmt.Sprint(item)); text != "" {
				out = append(out, text)
			}
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

func stringOr(raw interface{}, fallback string) string {
	text, ok := raw.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return fallback
	}
	return text
}

func floatValue(raw interface{}) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		n, err := v.Float64()
		return n, err == nil
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return n, err == nil
	default:
		return 0, false
	}
}
