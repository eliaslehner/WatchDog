from pathlib import Path

from agents.iac_scanner import IacScanner
from models import Severity

FIXTURE = str(Path(__file__).parent / "fixtures" / "vulnerable_project")


def test_detects_dockerfile_secrets():
    scanner = IacScanner(FIXTURE)
    findings = scanner.scan()
    docker = [f for f in findings if "Dockerfile" in f.description]
    assert len(docker) >= 1


def test_detects_compose_secrets():
    scanner = IacScanner(FIXTURE)
    findings = scanner.scan()
    compose = [f for f in findings if "docker-compose" in f.description.lower() or "docker-compose" in f.file_path]
    assert len(compose) >= 1


def test_detects_privileged_container():
    scanner = IacScanner(FIXTURE)
    findings = scanner.scan()
    priv = [f for f in findings if "rivileged" in f.description]
    assert len(priv) >= 1


def test_detects_terraform_secrets():
    scanner = IacScanner(FIXTURE)
    findings = scanner.scan()
    tf = [f for f in findings if "Terraform" in f.description or "main.tf" in f.file_path]
    assert len(tf) >= 1


def test_detects_open_security_group():
    scanner = IacScanner(FIXTURE)
    findings = scanner.scan()
    sg = [f for f in findings if "0.0.0.0/0" in f.description]
    assert len(sg) >= 1


def test_detects_k8s_security_issues():
    scanner = IacScanner(FIXTURE)
    findings = scanner.scan()
    k8s = [f for f in findings if "deployment.yaml" in f.file_path]
    assert len(k8s) >= 3  # privileged, runAsUser 0, hostNetwork, etc.
