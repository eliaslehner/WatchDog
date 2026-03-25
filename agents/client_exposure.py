import re
from pathlib import Path

from agents.base import BaseAgent
from models import Finding, Severity

SENSITIVE_ENV_PATTERN = re.compile(
    r'(?i)(?:SECRET|PASSWORD|PASSWD|PWD|PRIVATE|TOKEN|AUTH|CREDENTIAL|DB_|DATABASE_|'
    r'STRIPE_SECRET|API_SECRET|JWT_SECRET|SESSION_SECRET|ENCRYPTION|SIGNING)'
)

NEXTJS_PUBLIC_PREFIX = 'NEXT_PUBLIC_'
VITE_PREFIX = 'VITE_'
CRA_PREFIX = 'REACT_APP_'

NEXTJS_CLIENT_DIRS = {'pages', 'app', 'components', 'src/pages', 'src/app', 'src/components'}
NEXTJS_SERVER_PATTERNS = {
    'pages/api', 'app/api', 'src/pages/api', 'src/app/api',
    'middleware.ts', 'middleware.js',
}

PROCESS_ENV_PATTERN = re.compile(r'process\.env\.([A-Z_][A-Z0-9_]*)')
IMPORT_ENV_PATTERN = re.compile(r'import\.meta\.env\.([A-Z_][A-Z0-9_]*)')


class ClientExposureAnalyzer(BaseAgent):
    name = "client-exposure"

    def scan(self) -> list[Finding]:
        findings = []
        findings.extend(self._check_public_env_secrets())
        if self.framework in ('nextjs', 'nuxt', 'vite', 'create-react-app', 'sveltekit'):
            findings.extend(self._check_client_env_usage())
        return findings

    def _check_public_env_secrets(self) -> list[Finding]:
        findings = []
        env_files = [f for f in self.walk_files() if f.name.startswith('.env')]

        for fpath in env_files:
            for line_no, line in self.read_lines(fpath):
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if '=' not in stripped:
                    continue

                key = stripped.split('=', 1)[0].strip()
                value = stripped.split('=', 1)[1].strip().strip('"').strip("'")

                if not value:
                    continue

                is_public = (
                    key.startswith(NEXTJS_PUBLIC_PREFIX)
                    or key.startswith(VITE_PREFIX)
                    or key.startswith(CRA_PREFIX)
                )

                if is_public and SENSITIVE_ENV_PATTERN.search(key):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        file_path=self.rel_path(fpath),
                        line=line_no,
                        description=f"Sensitive variable '{key}' uses public prefix — exposed to client browser",
                        context=f"{key}=***",
                    ))

        return findings

    def _check_client_env_usage(self) -> list[Finding]:
        findings = []
        server_vars = self._collect_server_env_vars()
        if not server_vars:
            return findings

        js_exts = {'.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte', '.mjs'}
        client_files = [
            f for f in self.walk_files(extensions=js_exts)
            if self._is_client_file(f)
        ]

        for fpath in client_files:
            for line_no, line in self.read_lines(fpath):
                for match in PROCESS_ENV_PATTERN.finditer(line):
                    var_name = match.group(1)
                    if var_name in server_vars and not self._has_public_prefix(var_name):
                        findings.append(Finding(
                            severity=Severity.WARNING,
                            scanner=self.name,
                            file_path=self.rel_path(fpath),
                            line=line_no,
                            description=f"Server env var '{var_name}' referenced in client-side file",
                            context=line.strip()[:120],
                        ))

                for match in IMPORT_ENV_PATTERN.finditer(line):
                    var_name = match.group(1)
                    if SENSITIVE_ENV_PATTERN.search(var_name):
                        findings.append(Finding(
                            severity=Severity.WARNING,
                            scanner=self.name,
                            file_path=self.rel_path(fpath),
                            line=line_no,
                            description=f"Sensitive env var '{var_name}' accessed via import.meta.env in client code",
                            context=line.strip()[:120],
                        ))

        return findings

    def _collect_server_env_vars(self) -> set[str]:
        env_vars = set()
        for fpath in self.walk_files():
            if not fpath.name.startswith('.env'):
                continue
            for _, line in self.read_lines(fpath):
                stripped = line.strip()
                if stripped and not stripped.startswith('#') and '=' in stripped:
                    key = stripped.split('=', 1)[0].strip()
                    if not self._has_public_prefix(key):
                        env_vars.add(key)
        return env_vars

    def _has_public_prefix(self, var_name: str) -> bool:
        return (
            var_name.startswith(NEXTJS_PUBLIC_PREFIX)
            or var_name.startswith(VITE_PREFIX)
            or var_name.startswith(CRA_PREFIX)
        )

    def _is_client_file(self, fpath: Path) -> bool:
        rel = self.rel_path(fpath).replace('\\', '/')
        for server_pat in NEXTJS_SERVER_PATTERNS:
            if server_pat in rel:
                return False
        if self.framework == 'nextjs':
            if 'getServerSideProps' in (fpath.read_text(errors='replace')[:5000]):
                return False
        return True
