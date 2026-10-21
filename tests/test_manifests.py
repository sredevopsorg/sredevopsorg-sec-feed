"""Guards for the shipped Kubernetes manifests.

These are plain-text assertions on purpose: the project has no YAML dependency
and the manifests are small, so adding one would outweigh the benefit.
"""

from pathlib import Path

K8S = Path(__file__).resolve().parents[1] / "deploy" / "k8s"


def test_api_readiness_probes_the_database_endpoint():
    """Readiness must use /ready; /health never touches the database."""
    text = (K8S / "deployment.yaml").read_text(encoding="utf-8")
    readiness = text.split("readinessProbe:", 1)[1].split("livenessProbe:", 1)[0]
    liveness = text.split("livenessProbe:", 1)[1]
    assert "path: /ready" in readiness
    assert "path: /health" in liveness


def test_shipped_configmap_never_allows_wildcard_cors():
    """CORS fails closed by default; a shipped manifest must not opt out."""
    text = (K8S / "configmap.yaml").read_text(encoding="utf-8")
    assert 'CORS_ORIGINS: "*"' not in text
    assert "CORS_ORIGINS: '*'" not in text


def test_containers_drop_all_capabilities():
    for name in ("deployment.yaml", "frontend.yaml"):
        text = (K8S / name).read_text(encoding="utf-8")
        assert 'drop: ["ALL"]' in text, name


def test_api_container_has_a_read_only_root_filesystem():
    text = (K8S / "deployment.yaml").read_text(encoding="utf-8")
    assert "readOnlyRootFilesystem: true" in text
