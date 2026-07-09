from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping

from zarch.extensions.base import ZArchExtension


DEFAULT_CONFIG: Dict[str, Any] = {
    "location": None,
    "key_ring": "",
    "key_id": "",
    "purpose": "ENCRYPT_DECRYPT",
    "rotation_period_days": None,
    "enable_api": True,
    "preflight_only": False,
    "retry_attempts": 3,
    "retry_initial_delay_seconds": 1.0,
    "retry_backoff_multiplier": 2.0,
}

CANONICAL_PURPOSE_ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
ALLOWED_PURPOSES = {CANONICAL_PURPOSE_ENCRYPT_DECRYPT}
PURPOSE_ALIASES = {
    "ENCRYPT_DECRYPT": CANONICAL_PURPOSE_ENCRYPT_DECRYPT,
    "ENCRYPTION": CANONICAL_PURPOSE_ENCRYPT_DECRYPT,
}
PURPOSE_TO_GCLOUD = {CANONICAL_PURPOSE_ENCRYPT_DECRYPT: "encryption"}
BOOL_TRUE_VALUES = {"true", "1", "yes", "y", "on"}
BOOL_FALSE_VALUES = {"false", "0", "no", "n", "off"}
RESOURCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
LOCATION_PATTERN = re.compile(r"^[a-z0-9-]{2,64}$")
NOT_FOUND_PATTERNS = (
    r"\bnot[_\s-]?found\b",
    r"\b404\b",
    r"does not exist",
    r"was not found",
    r"requested entity was not found",
)
TRANSIENT_ERROR_PATTERNS = (
    r"\b429\b",
    r"\b500\b",
    r"\b502\b",
    r"\b503\b",
    r"\b504\b",
    r"rate limit",
    r"resource exhausted",
    r"temporar(?:y|ily) unavailable",
    r"deadline exceeded",
    r"timed out",
    r"connection reset",
    r"internal error",
    r"backend error",
)


class Extension(ZArchExtension):
    """
    Z-Arch extension: kms-bootstrap
    """

    def claim(self, extension_name: str, extension_block: Dict[str, Any]) -> bool:
        return extension_block.get("type") == "kms-bootstrap"

    async def post_project_bootstrap(
        self,
        project_context,
        extension_configuration: Dict[str, Any],
    ) -> None:
        settings = self._resolve_settings(extension_configuration, project_context)
        if settings["preflight_only"]:
            project_context.log(
                "kms-bootstrap: running in preflight_only mode (no mutations)."
            )

        if settings["enable_api"]:
            if settings["preflight_only"]:
                project_context.log(
                    "kms-bootstrap: preflight_only=true, skipping API enable mutation."
                )
            else:
                project_context.log("kms-bootstrap: enabling Cloud KMS API.")
                await self._run_gcloud(
                    project_context,
                    ["services", "enable", "cloudkms.googleapis.com", "--quiet"],
                    "enable Cloud KMS API",
                    settings=settings,
                )

        project_context.log(
            "kms-bootstrap: ensuring key ring "
            f"'{settings['key_ring']}' in location '{settings['location']}'."
        )
        await self._ensure_key_ring(project_context, settings)

        project_context.log(
            "kms-bootstrap: ensuring crypto key "
            f"'{settings['key_id']}' in key ring '{settings['key_ring']}'."
        )
        await self._ensure_crypto_key(project_context, settings)

    def _resolve_settings(
        self,
        extension_configuration: Mapping[str, Any],
        project_context,
    ) -> Dict[str, Any]:
        if not isinstance(extension_configuration, Mapping):
            raise RuntimeError("kms-bootstrap config must be a mapping.")

        config_values: Dict[str, Any] = {}
        nested = extension_configuration.get("config")
        if isinstance(nested, Mapping):
            config_values.update(nested)
        else:
            config_values.update(extension_configuration)

        merged = dict(DEFAULT_CONFIG)
        merged.update(config_values)

        location = str(merged.get("location") or project_context.region).strip().lower()
        if not location:
            raise RuntimeError("location is required and must be non-empty.")
        if not LOCATION_PATTERN.fullmatch(location):
            raise RuntimeError(
                "location must contain only lowercase letters, numbers, and hyphens."
            )
        merged["location"] = location

        key_ring = str(merged.get("key_ring", "")).strip()
        if not key_ring:
            raise RuntimeError("key_ring is required and must be non-empty.")
        if not RESOURCE_ID_PATTERN.fullmatch(key_ring):
            raise RuntimeError(
                "key_ring must match pattern: [A-Za-z0-9_-]{1,63}."
            )
        merged["key_ring"] = key_ring

        key_id = str(merged.get("key_id", "")).strip()
        if not key_id:
            raise RuntimeError("key_id is required and must be non-empty.")
        if not RESOURCE_ID_PATTERN.fullmatch(key_id):
            raise RuntimeError(
                "key_id must match pattern: [A-Za-z0-9_-]{1,63}."
            )
        merged["key_id"] = key_id

        purpose = self._normalize_purpose(merged.get("purpose"))
        if purpose not in ALLOWED_PURPOSES:
            raise RuntimeError(
                "Invalid purpose. Expected one of: "
                + ", ".join(sorted(ALLOWED_PURPOSES))
            )
        merged["purpose"] = purpose

        rotation_period_days_raw = merged.get("rotation_period_days")
        if rotation_period_days_raw in (None, ""):
            merged["rotation_period_days"] = None
        else:
            rotation_period_days = self._parse_int(
                rotation_period_days_raw,
                "rotation_period_days",
            )
            if rotation_period_days <= 0:
                raise RuntimeError("rotation_period_days must be a positive integer.")
            merged["rotation_period_days"] = rotation_period_days

        merged["enable_api"] = self._parse_bool(
            merged.get("enable_api"),
            "enable_api",
        )
        merged["preflight_only"] = self._parse_bool(
            merged.get("preflight_only"),
            "preflight_only",
        )

        retry_attempts = self._parse_int(
            merged.get("retry_attempts"),
            "retry_attempts",
        )
        if retry_attempts <= 0:
            raise RuntimeError("retry_attempts must be a positive integer.")
        merged["retry_attempts"] = retry_attempts

        retry_initial_delay_seconds = self._parse_float(
            merged.get("retry_initial_delay_seconds"),
            "retry_initial_delay_seconds",
        )
        if retry_initial_delay_seconds < 0:
            raise RuntimeError("retry_initial_delay_seconds must be >= 0.")
        merged["retry_initial_delay_seconds"] = retry_initial_delay_seconds

        retry_backoff_multiplier = self._parse_float(
            merged.get("retry_backoff_multiplier"),
            "retry_backoff_multiplier",
        )
        if retry_backoff_multiplier < 1:
            raise RuntimeError("retry_backoff_multiplier must be >= 1.")
        merged["retry_backoff_multiplier"] = retry_backoff_multiplier

        return merged

    async def _ensure_key_ring(
        self,
        project_context,
        settings: Mapping[str, Any],
    ) -> Dict[str, Any]:
        key_ring = str(settings["key_ring"])
        location = str(settings["location"])

        describe_output, describe_code = await self._gcloud_with_project(
            project_context,
            [
                "kms",
                "keyrings",
                "describe",
                key_ring,
                f"--location={location}",
                "--format=json",
            ],
        )
        if describe_code == 0:
            key_ring_obj = self._parse_json(describe_output, "key ring describe output")
            if not isinstance(key_ring_obj, Mapping):
                raise RuntimeError(
                    "Expected object JSON in key ring describe output, "
                    f"got {type(key_ring_obj).__name__}."
                )
            self._validate_key_ring_shape(key_ring_obj, settings)
            return dict(key_ring_obj)

        if not self._is_not_found_error(describe_output):
            raise RuntimeError(
                f"Failed to describe key ring '{key_ring}': {describe_output}"
            )
        if settings["preflight_only"]:
            raise RuntimeError(
                f"Preflight failed: key ring '{key_ring}' does not exist "
                f"in location '{location}'."
            )

        await self._run_gcloud(
            project_context,
            [
                "kms",
                "keyrings",
                "create",
                key_ring,
                f"--location={location}",
                "--quiet",
            ],
            f"create key ring '{key_ring}'",
            settings=settings,
        )

        describe_after = await self._run_gcloud(
            project_context,
            [
                "kms",
                "keyrings",
                "describe",
                key_ring,
                f"--location={location}",
                "--format=json",
            ],
            f"describe key ring '{key_ring}' after creation",
            settings=settings,
        )
        key_ring_obj = self._parse_json(describe_after, "key ring describe output")
        if not isinstance(key_ring_obj, Mapping):
            raise RuntimeError(
                "Expected object JSON in key ring describe output, "
                f"got {type(key_ring_obj).__name__}."
            )
        self._validate_key_ring_shape(key_ring_obj, settings)
        return dict(key_ring_obj)

    async def _ensure_crypto_key(
        self,
        project_context,
        settings: Mapping[str, Any],
    ) -> Dict[str, Any]:
        key_id = str(settings["key_id"])
        key_ring = str(settings["key_ring"])
        location = str(settings["location"])

        describe_output, describe_code = await self._gcloud_with_project(
            project_context,
            [
                "kms",
                "keys",
                "describe",
                key_id,
                f"--keyring={key_ring}",
                f"--location={location}",
                "--format=json",
            ],
        )

        if describe_code == 0:
            key_obj = self._parse_json(describe_output, "crypto key describe output")
            if not isinstance(key_obj, Mapping):
                raise RuntimeError(
                    "Expected object JSON in crypto key describe output, "
                    f"got {type(key_obj).__name__}."
                )
            self._validate_crypto_key_shape(key_obj, settings)
            await self._reconcile_rotation(project_context, key_obj, settings)
            return dict(key_obj)

        if not self._is_not_found_error(describe_output):
            raise RuntimeError(
                f"Failed to describe crypto key '{key_id}': {describe_output}"
            )
        if settings["preflight_only"]:
            raise RuntimeError(
                f"Preflight failed: crypto key '{key_id}' does not exist "
                f"in key ring '{key_ring}' at location '{location}'."
            )

        create_args = [
            "kms",
            "keys",
            "create",
            key_id,
            f"--keyring={key_ring}",
            f"--location={location}",
            f"--purpose={self._purpose_to_gcloud(str(settings['purpose']))}",
            "--quiet",
        ]
        rotation_period_days = settings.get("rotation_period_days")
        if isinstance(rotation_period_days, int):
            create_args.extend(
                [
                    f"--rotation-period={self._rotation_period_string(rotation_period_days)}",
                    f"--next-rotation-time={self._next_rotation_time_iso(rotation_period_days)}",
                ]
            )

        await self._run_gcloud(
            project_context,
            create_args,
            f"create crypto key '{key_id}'",
            settings=settings,
        )

        describe_after = await self._run_gcloud(
            project_context,
            [
                "kms",
                "keys",
                "describe",
                key_id,
                f"--keyring={key_ring}",
                f"--location={location}",
                "--format=json",
            ],
            f"describe crypto key '{key_id}' after creation",
            settings=settings,
        )
        key_obj = self._parse_json(describe_after, "crypto key describe output")
        if not isinstance(key_obj, Mapping):
            raise RuntimeError(
                "Expected object JSON in crypto key describe output, "
                f"got {type(key_obj).__name__}."
            )
        self._validate_crypto_key_shape(key_obj, settings)
        await self._reconcile_rotation(project_context, key_obj, settings)
        return dict(key_obj)

    def _validate_key_ring_shape(
        self,
        key_ring_obj: Mapping[str, Any],
        settings: Mapping[str, Any],
    ) -> None:
        name = str(key_ring_obj.get("name", "")).strip()
        if not name:
            return

        expected_suffix = (
            f"/locations/{settings['location']}/keyRings/{settings['key_ring']}"
        )
        if not name.endswith(expected_suffix):
            raise RuntimeError(
                "Existing key ring settings are incompatible with extension config: "
                f"expected suffix '{expected_suffix}', got name='{name}'."
            )

    def _validate_crypto_key_shape(
        self,
        key_obj: Mapping[str, Any],
        settings: Mapping[str, Any],
    ) -> None:
        mismatches: list[str] = []

        name = str(key_obj.get("name", "")).strip()
        if name:
            expected_suffix = (
                f"/locations/{settings['location']}"
                f"/keyRings/{settings['key_ring']}"
                f"/cryptoKeys/{settings['key_id']}"
            )
            if not name.endswith(expected_suffix):
                mismatches.append(
                    f"name expected_suffix={expected_suffix} actual={name}"
                )

        raw_purpose = key_obj.get("purpose")
        if raw_purpose:
            purpose = self._normalize_purpose(raw_purpose)
        else:
            purpose = ""
        if purpose and purpose != str(settings["purpose"]).upper():
            mismatches.append(
                f"purpose expected={settings['purpose']} actual={raw_purpose}"
            )

        if mismatches:
            raise RuntimeError(
                "Existing crypto key settings are incompatible with extension config: "
                + "; ".join(mismatches)
            )

    async def _reconcile_rotation(
        self,
        project_context,
        key_obj: Mapping[str, Any],
        settings: Mapping[str, Any],
    ) -> None:
        rotation_period_days = settings.get("rotation_period_days")
        if not isinstance(rotation_period_days, int):
            return

        current_rotation = key_obj.get("rotationPeriod")
        if self._rotation_matches(current_rotation, rotation_period_days):
            return
        if settings["preflight_only"]:
            raise RuntimeError(
                "Preflight failed: crypto key rotation period drift detected "
                f"(expected={self._rotation_period_string(rotation_period_days)} "
                f"actual={current_rotation!r})."
            )

        await self._run_gcloud(
            project_context,
            [
                "kms",
                "keys",
                "update",
                str(settings["key_id"]),
                f"--keyring={settings['key_ring']}",
                f"--location={settings['location']}",
                f"--rotation-period={self._rotation_period_string(rotation_period_days)}",
                f"--next-rotation-time={self._next_rotation_time_iso(rotation_period_days)}",
                "--quiet",
            ],
            f"update rotation for crypto key '{settings['key_id']}'",
            settings=settings,
        )

    def _rotation_matches(self, raw_rotation_period: Any, rotation_period_days: int) -> bool:
        if raw_rotation_period is None:
            return False
        raw = str(raw_rotation_period).strip()
        match = re.fullmatch(r"(\d+(?:\.\d+)?)s", raw)
        if not match:
            return False
        try:
            current_seconds = int(float(match.group(1)))
        except (TypeError, ValueError):
            return False
        return current_seconds == rotation_period_days * 86400

    def _rotation_period_string(self, rotation_period_days: int) -> str:
        return f"{rotation_period_days * 86400}s"

    def _next_rotation_time_iso(self, rotation_period_days: int) -> str:
        next_rotation = datetime.now(timezone.utc) + timedelta(days=rotation_period_days)
        return next_rotation.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    async def _run_gcloud(
        self,
        project_context,
        args: list[str],
        action: str,
        *,
        settings: Mapping[str, Any] | None = None,
    ) -> str:
        retry_attempts = int((settings or {}).get("retry_attempts", 1))
        delay_seconds = float((settings or {}).get("retry_initial_delay_seconds", 0))
        backoff_multiplier = float((settings or {}).get("retry_backoff_multiplier", 1))

        attempt = 1
        while True:
            output, code = await self._gcloud_with_project(project_context, args)
            if code == 0:
                return output

            if attempt >= retry_attempts or not self._is_transient_error(output, code):
                raise RuntimeError(
                    f"Failed to {action} after {attempt} attempt(s): {output}"
                )

            project_context.log(
                f"kms-bootstrap: transient gcloud failure on '{action}', "
                f"retrying attempt {attempt + 1}/{retry_attempts}.",
                level="warn",
            )
            if delay_seconds > 0:
                self._sleep(delay_seconds)
                delay_seconds *= backoff_multiplier
            attempt += 1

    async def _gcloud_with_project(self, project_context, args: list[str]) -> tuple[str, int]:
        full_args = list(args)
        if not any(arg == "--project" or arg.startswith("--project=") for arg in full_args):
            full_args.extend(["--project", project_context.id])
        return await project_context.gcloud(full_args)

    def _parse_json(self, output: str, source: str) -> Any:
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Could not parse JSON from {source}: {exc}") from exc

    def _parse_bool(self, value: Any, field_name: str) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in BOOL_TRUE_VALUES:
                return True
            if normalized in BOOL_FALSE_VALUES:
                return False
        raise RuntimeError(f"Invalid boolean for {field_name}: {value!r}")

    def _normalize_purpose(self, value: Any) -> str:
        normalized = str(value or "").strip().upper()
        if not normalized:
            return normalized
        if normalized in PURPOSE_ALIASES:
            return PURPOSE_ALIASES[normalized]
        return normalized

    def _purpose_to_gcloud(self, canonical_purpose: str) -> str:
        mapped = PURPOSE_TO_GCLOUD.get(canonical_purpose)
        if mapped is None:
            raise RuntimeError(
                f"Unsupported canonical purpose for gcloud conversion: {canonical_purpose!r}"
            )
        return mapped

    def _parse_int(self, value: Any, field_name: str) -> int:
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Invalid integer for {field_name}: {value!r}") from exc

    def _parse_float(self, value: Any, field_name: str) -> float:
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Invalid float for {field_name}: {value!r}") from exc

    def _sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def _is_not_found_error(self, output: str) -> bool:
        lowered = (output or "").lower()
        return any(re.search(pattern, lowered) for pattern in NOT_FOUND_PATTERNS)

    def _is_transient_error(self, output: str, code: int) -> bool:
        if code == 0:
            return False
        lowered = (output or "").lower()
        return any(re.search(pattern, lowered) for pattern in TRANSIENT_ERROR_PATTERNS)
