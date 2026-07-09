import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zarch_ext_kms_bootstrap.extension import Extension


class DummyContext:
    def __init__(self, *, project_id="demo-project", region="us-central1", responder=None):
        self.id = project_id
        self.region = region
        self._responder = responder or (lambda args: ("{}", 0))
        self.gcloud_calls = []
        self.logs = []

    async def gcloud(self, args):
        self.gcloud_calls.append(list(args))
        return self._responder(args)

    def log(self, message, level=None):
        self.logs.append((message, level))


def _key_ring_json(project_id: str, location: str, key_ring: str) -> str:
    return (
        "{"
        f"\"name\":\"projects/{project_id}/locations/{location}/keyRings/{key_ring}\""
        "}"
    )


def _key_json(project_id: str, location: str, key_ring: str, key_id: str, *, purpose: str, rotation: str | None = None) -> str:
    payload = {
        "name": (
            f"projects/{project_id}/locations/{location}/"
            f"keyRings/{key_ring}/cryptoKeys/{key_id}"
        ),
        "purpose": purpose,
    }
    if rotation is not None:
        payload["rotationPeriod"] = rotation
    import json

    return json.dumps(payload)


def test_resolve_settings_parses_and_normalizes_values():
    ext = Extension()
    ctx = DummyContext(region="us-east4")
    cfg = {
        "config": {
            "location": "US-EAST4",
            "key_ring": "  app-ring  ",
            "key_id": "  wrapper-key ",
            "purpose": "encrypt_decrypt",
            "rotation_period_days": "90",
            "enable_api": "false",
        }
    }

    resolved = ext._resolve_settings(cfg, ctx)

    assert resolved["location"] == "us-east4"
    assert resolved["key_ring"] == "app-ring"
    assert resolved["key_id"] == "wrapper-key"
    assert resolved["purpose"] == "ENCRYPT_DECRYPT"
    assert resolved["rotation_period_days"] == 90
    assert resolved["enable_api"] is False


def test_resolve_settings_accepts_purpose_alias_encryption():
    ext = Extension()
    ctx = DummyContext(region="us-east4")
    cfg = {
        "config": {
            "location": "us-east4",
            "key_ring": "app-ring",
            "key_id": "wrapper-key",
            "purpose": "encryption",
        }
    }

    resolved = ext._resolve_settings(cfg, ctx)
    assert resolved["purpose"] == "ENCRYPT_DECRYPT"


def test_resolve_settings_rejects_invalid_shape():
    ext = Extension()
    ctx = DummyContext()

    with pytest.raises(RuntimeError, match="key_ring is required"):
        ext._resolve_settings({"config": {"key_id": "k"}}, ctx)

    with pytest.raises(RuntimeError, match="Invalid purpose"):
        ext._resolve_settings(
            {"config": {"key_ring": "r", "key_id": "k", "purpose": "SIGN_VERIFY"}},
            ctx,
        )

    with pytest.raises(RuntimeError, match="rotation_period_days must be a positive integer"):
        ext._resolve_settings(
            {"config": {"key_ring": "r", "key_id": "k", "rotation_period_days": 0}},
            ctx,
        )

    with pytest.raises(RuntimeError, match="retry_attempts must be a positive integer"):
        ext._resolve_settings(
            {"config": {"key_ring": "r", "key_id": "k", "retry_attempts": 0}},
            ctx,
        )


def test_create_command_shape_when_resources_missing():
    ext = Extension()
    state = {"ring": False, "key": False}
    calls = []

    def responder(args):
        calls.append(list(args))
        if args[:3] == ["kms", "keyrings", "describe"]:
            if state["ring"]:
                return (_key_ring_json("demo-project", "us-central1", "demo-ring"), 0)
            return ("not found", 1)
        if args[:3] == ["kms", "keyrings", "create"]:
            state["ring"] = True
            return ("{}", 0)
        if args[:3] == ["kms", "keys", "describe"]:
            if state["key"]:
                return (
                    _key_json(
                        "demo-project",
                        "us-central1",
                        "demo-ring",
                        "demo-key",
                        purpose="ENCRYPT_DECRYPT",
                        rotation="7776000s",
                    ),
                    0,
                )
            return ("not found", 1)
        if args[:3] == ["kms", "keys", "create"]:
            state["key"] = True
            return ("{}", 0)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    asyncio.run(ext.post_project_bootstrap(
        ctx,
        {
            "config": {
                "location": "us-central1",
                "key_ring": "demo-ring",
                "key_id": "demo-key",
                "rotation_period_days": 90,
            }
        },
    ))

    enable_calls = [c for c in calls if c[:2] == ["services", "enable"]]
    ring_create_calls = [c for c in calls if c[:3] == ["kms", "keyrings", "create"]]
    key_create_calls = [c for c in calls if c[:3] == ["kms", "keys", "create"]]

    assert len(enable_calls) == 1
    assert len(ring_create_calls) == 1
    assert len(key_create_calls) == 1

    ring_create = ring_create_calls[0]
    assert ring_create[3] == "demo-ring"
    assert "--location=us-central1" in ring_create
    assert "--project" in ring_create

    key_create = key_create_calls[0]
    assert key_create[3] == "demo-key"
    assert "--keyring=demo-ring" in key_create
    assert "--location=us-central1" in key_create
    assert "--purpose=encryption" in key_create
    assert "--rotation-period=7776000s" in key_create
    assert any(part.startswith("--next-rotation-time=") for part in key_create)
    assert "--project" in key_create


def test_idempotency_skips_create_and_update_for_compliant_resources():
    ext = Extension()
    calls = []

    def responder(args):
        calls.append(list(args))
        if args[:3] == ["kms", "keyrings", "describe"]:
            return (_key_ring_json("demo-project", "us-central1", "demo-ring"), 0)
        if args[:3] == ["kms", "keys", "describe"]:
            return (
                _key_json(
                    "demo-project",
                    "us-central1",
                    "demo-ring",
                    "demo-key",
                    purpose="ENCRYPT_DECRYPT",
                    rotation="7776000s",
                ),
                0,
            )
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    asyncio.run(ext.post_project_bootstrap(
        ctx,
        {
            "config": {
                "location": "us-central1",
                "key_ring": "demo-ring",
                "key_id": "demo-key",
                "rotation_period_days": 90,
                "enable_api": False,
            }
        },
    ))

    assert [c for c in calls if c[:3] == ["kms", "keyrings", "create"]] == []
    assert [c for c in calls if c[:3] == ["kms", "keys", "create"]] == []
    assert [c for c in calls if c[:3] == ["kms", "keys", "update"]] == []
    assert [c for c in calls if c[:2] == ["services", "enable"]] == []


def test_idempotency_accepts_describe_purpose_encryption_alias():
    ext = Extension()
    calls = []

    def responder(args):
        calls.append(list(args))
        if args[:3] == ["kms", "keyrings", "describe"]:
            return (_key_ring_json("demo-project", "us-central1", "demo-ring"), 0)
        if args[:3] == ["kms", "keys", "describe"]:
            return (
                _key_json(
                    "demo-project",
                    "us-central1",
                    "demo-ring",
                    "demo-key",
                    purpose="ENCRYPTION",
                    rotation="7776000s",
                ),
                0,
            )
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    asyncio.run(ext.post_project_bootstrap(
        ctx,
        {
            "config": {
                "location": "us-central1",
                "key_ring": "demo-ring",
                "key_id": "demo-key",
                "rotation_period_days": 90,
                "enable_api": False,
            }
        },
    ))

    assert [c for c in calls if c[:3] == ["kms", "keys", "update"]] == []
    assert [c for c in calls if c[:3] == ["kms", "keys", "create"]] == []


def test_rotation_drift_updates_key_with_expected_flags():
    ext = Extension()
    calls = []

    def responder(args):
        calls.append(list(args))
        if args[:3] == ["kms", "keyrings", "describe"]:
            return (_key_ring_json("demo-project", "us-central1", "demo-ring"), 0)
        if args[:3] == ["kms", "keys", "describe"]:
            return (
                _key_json(
                    "demo-project",
                    "us-central1",
                    "demo-ring",
                    "demo-key",
                    purpose="ENCRYPT_DECRYPT",
                    rotation="2592000s",
                ),
                0,
            )
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    asyncio.run(ext.post_project_bootstrap(
        ctx,
        {
            "config": {
                "location": "us-central1",
                "key_ring": "demo-ring",
                "key_id": "demo-key",
                "rotation_period_days": 90,
                "enable_api": False,
            }
        },
    ))

    update_calls = [c for c in calls if c[:3] == ["kms", "keys", "update"]]
    assert len(update_calls) == 1
    update_call = update_calls[0]
    assert update_call[3] == "demo-key"
    assert "--keyring=demo-ring" in update_call
    assert "--location=us-central1" in update_call
    assert "--rotation-period=7776000s" in update_call
    assert any(part.startswith("--next-rotation-time=") for part in update_call)
    assert "--project" in update_call


def test_fail_closed_on_incompatible_existing_key_shape():
    ext = Extension()
    calls = []

    def responder(args):
        calls.append(list(args))
        if args[:3] == ["kms", "keyrings", "describe"]:
            return (_key_ring_json("demo-project", "us-central1", "demo-ring"), 0)
        if args[:3] == ["kms", "keys", "describe"]:
            return (
                _key_json(
                    "demo-project",
                    "us-central1",
                    "demo-ring",
                    "demo-key",
                    purpose="ASYMMETRIC_SIGN",
                    rotation="7776000s",
                ),
                0,
            )
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    with pytest.raises(RuntimeError, match="incompatible"):
        asyncio.run(ext.post_project_bootstrap(
            ctx,
            {
                "config": {
                    "location": "us-central1",
                    "key_ring": "demo-ring",
                    "key_id": "demo-key",
                    "rotation_period_days": 90,
                    "enable_api": False,
                }
            },
        ))

    assert [c for c in calls if c[:3] == ["kms", "keys", "update"]] == []
    assert [c for c in calls if c[:3] == ["kms", "keys", "create"]] == []


def test_preflight_mode_fails_without_mutating_when_keyring_missing():
    ext = Extension()
    calls = []

    def responder(args):
        calls.append(list(args))
        if args[:3] == ["kms", "keyrings", "describe"]:
            return ("NOT_FOUND: Requested entity was not found.", 1)
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    with pytest.raises(RuntimeError, match="Preflight failed: key ring"):
        asyncio.run(ext.post_project_bootstrap(
            ctx,
            {
                "config": {
                    "location": "us-central1",
                    "key_ring": "demo-ring",
                    "key_id": "demo-key",
                    "preflight_only": True,
                    "enable_api": True,
                }
            },
        ))

    assert [c for c in calls if c[:2] == ["services", "enable"]] == []
    assert [c for c in calls if c[:3] == ["kms", "keyrings", "create"]] == []
    assert [c for c in calls if c[:3] == ["kms", "keys", "create"]] == []
    assert [c for c in calls if c[:3] == ["kms", "keys", "update"]] == []


def test_transient_error_retries_then_succeeds():
    ext = Extension()
    calls = []
    state = {"enable_attempts": 0}

    def responder(args):
        calls.append(list(args))
        if args[:2] == ["services", "enable"]:
            state["enable_attempts"] += 1
            if state["enable_attempts"] < 3:
                return ("429 RESOURCE_EXHAUSTED: rate limit", 1)
            return ("ok", 0)
        if args[:3] == ["kms", "keyrings", "describe"]:
            return (_key_ring_json("demo-project", "us-central1", "demo-ring"), 0)
        if args[:3] == ["kms", "keys", "describe"]:
            return (
                _key_json(
                    "demo-project",
                    "us-central1",
                    "demo-ring",
                    "demo-key",
                    purpose="ENCRYPT_DECRYPT",
                ),
                0,
            )
        return ("{}", 0)

    ctx = DummyContext(responder=responder)
    asyncio.run(ext.post_project_bootstrap(
        ctx,
        {
            "config": {
                "location": "us-central1",
                "key_ring": "demo-ring",
                "key_id": "demo-key",
                "retry_attempts": 3,
                "retry_initial_delay_seconds": 0,
                "retry_backoff_multiplier": 2,
            }
        },
    ))

    enable_calls = [c for c in calls if c[:2] == ["services", "enable"]]
    assert len(enable_calls) == 3
