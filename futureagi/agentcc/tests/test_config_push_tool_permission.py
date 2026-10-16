"""Dashboard tool-permissions checks must reach the gateway recogniser.

Regression for https://github.com/future-agi/future-agi/issues/3230.
``_RULE_PROVIDER_DEFAULTS`` used to send ``tool_permissions``. The gateway
recogniser ``toolperm.IsToolPermConfig`` accepts ``tool_permission`` (and,
after the gateway half of this fix, the historical plural as well). A
mismatch meant the dynamic factory built nothing and a denied tool call
reached the provider.
"""

import pytest

from agentcc.services.config_push import (
    _RULE_PROVIDER_DEFAULTS,
    _transform_guardrails,
)


def test_tool_permissions_provider_matches_gateway_recogniser():
    assert _RULE_PROVIDER_DEFAULTS["tool-permissions"] == "tool_permission"


@pytest.mark.parametrize(
    "guardrails",
    [
        {
            "checks": [
                {
                    "name": "tool-permissions",
                    "enabled": True,
                    "action": "block",
                    "config": {"mode": "denylist", "tools": ["file_delete"]},
                }
            ]
        },
        {
            "rules": [
                {
                    "name": "tool-permissions",
                    "enabled": True,
                    "action": "block",
                    "config": {"mode": "denylist", "tools": ["file_delete"]},
                }
            ]
        },
    ],
    ids=["checks-list", "rules-list"],
)
def test_transform_guardrails_pushes_singular_tool_permission_provider(guardrails):
    pushed = _transform_guardrails(guardrails)
    check = pushed["checks"]["tool-permissions"]
    assert check["config"]["provider"] == "tool_permission"
    assert check["config"]["mode"] == "denylist"
    assert check["config"]["tools"] == ["file_delete"]
