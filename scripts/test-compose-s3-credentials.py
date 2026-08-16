#!/usr/bin/env python3
"""Verify that every bundled Compose topology wires one S3 credential pair."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose-volume.yml",
    "docker-compose.chat-federation.yml",
)
TEST_ACCESS_KEY = "compose-regression-access"
TEST_SECRET_KEY = "compose-regression-secret"


def render_compose(compose_file: str) -> dict:
    environment = os.environ.copy()
    environment.update(
        {
            "POSTGRES_PASSWORD": "compose-regression-postgres",
            "JWT_SECRET": "compose-regression-jwt-secret-at-least-32-bytes",
            "S3_ACCESS_KEY": TEST_ACCESS_KEY,
            "S3_SECRET_KEY": TEST_SECRET_KEY,
        }
    )
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--file",
            compose_file,
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def require_equal(
    compose_file: str,
    service_name: str,
    actual: object,
    expected: object,
) -> None:
    if actual != expected:
        raise AssertionError(
            f"{compose_file}: {service_name} does not share the configured S3 credentials"
        )


def verify(compose_file: str) -> None:
    services = render_compose(compose_file)["services"]
    s3_service = services["seaweedfs-s3"]
    s3_environment = s3_service.get("environment", {})
    s3_access_key = s3_environment.get("AWS_ACCESS_KEY_ID")
    s3_secret_key = s3_environment.get("AWS_SECRET_ACCESS_KEY")

    if not s3_access_key or not s3_secret_key:
        raise AssertionError(
            f"{compose_file}: seaweedfs-s3 must receive AWS fallback credentials"
        )
    if "-config" in str(s3_service.get("command", "")):
        raise AssertionError(
            f"{compose_file}: seaweedfs-s3 must not use a static credential file"
        )

    for volume in s3_service.get("volumes", []):
        if "seaweedfs-s3.json" in str(volume):
            raise AssertionError(
                f"{compose_file}: seaweedfs-s3 must not mount a static credential file"
            )

    for service_name, service in services.items():
        environment = service.get("environment", {})
        if service_name.startswith("seaweedfs-init"):
            require_equal(
                compose_file,
                service_name,
                environment.get("AWS_ACCESS_KEY_ID"),
                s3_access_key,
            )
            require_equal(
                compose_file,
                service_name,
                environment.get("AWS_SECRET_ACCESS_KEY"),
                s3_secret_key,
            )
        elif service_name.startswith("backend"):
            require_equal(
                compose_file,
                service_name,
                environment.get("S3_ACCESS_KEY"),
                s3_access_key,
            )
            require_equal(
                compose_file,
                service_name,
                environment.get("S3_SECRET_KEY"),
                s3_secret_key,
            )


def main() -> None:
    for compose_file in COMPOSE_FILES:
        verify(compose_file)
    print("Compose S3 credential wiring verified.")


if __name__ == "__main__":
    main()
