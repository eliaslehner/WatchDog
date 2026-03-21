from abc import ABC, abstractmethod
from pathlib import Path

from models import Finding


IGNORE_DIRS = {
    '.git', 'node_modules', '.venv', 'venv', '__pycache__',
    '.tox', '.mypy_cache', '.pytest_cache', '.cache',
    'vendor', '.terraform', 'coverage', '.nyc_output',
    '.egg-info', '.eggs', 'site-packages',
}

BUILD_DIRS = {'.next', 'dist', 'build', 'out', '_site', 'public'}

TEXT_SUFFIXES = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte', '.mjs', '.cjs',
    '.rb', '.go', '.java', '.rs', '.php', '.cs', '.kt', '.swift', '.scala',
    '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.properties',
    '.env', '.sh', '.bash', '.zsh', '.fish', '.bat', '.ps1', '.cmd',
    '.tf', '.hcl', '.tfvars',
    '.html', '.htm', '.css', '.scss', '.less', '.sass',
    '.md', '.txt', '.rst', '.xml', '.csv', '.sql',
    '.lock', '.sum',
    '.gradle', '.sbt',
    '.graphql', '.gql', '.prisma',
}

SCANNABLE_NAMES = {
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    'Makefile', 'Gemfile', 'Rakefile', 'Procfile', 'Vagrantfile',
    '.gitignore', '.dockerignore', '.helmignore',
    '.env', '.env.local', '.env.development', '.env.production',
    '.env.staging', '.env.example', '.env.sample', '.env.test',
    '.babelrc', '.eslintrc', '.prettierrc',
}


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self, path: str, framework: str | None = None, target: str | None = None, exclude: list[str] | None = None):
        self.path = Path(path)
        self.framework = framework
        self.target = target
        self.exclude = set(exclude) if exclude else set()

    @abstractmethod
    def scan(self) -> list[Finding]:
        ...

    def walk_files(
        self,
        extra_ignore: set[str] | None = None,
        include_build: bool = False,
        extensions: set[str] | None = None,
    ) -> list[Path]:
        ignore = IGNORE_DIRS | self.exclude | (extra_ignore or set())
        if not include_build:
            ignore = ignore | BUILD_DIRS
        exts = extensions if extensions is not None else TEXT_SUFFIXES

        results = []
        for item in self.path.rglob('*'):
            if not item.is_file():
                continue
            try:
                rel = item.relative_to(self.path)
            except ValueError:
                continue
            if any(part in ignore for part in rel.parts):
                continue
            if item.name in SCANNABLE_NAMES or item.suffix.lower() in exts:
                results.append(item)
        return results

    def read_lines(self, file_path: Path) -> list[tuple[int, str]]:
        try:
            text = file_path.read_text(errors='replace')
            return [(i + 1, line) for i, line in enumerate(text.splitlines())]
        except OSError:
            return []

    def rel_path(self, file_path: Path) -> str:
        try:
            return str(file_path.relative_to(self.path))
        except ValueError:
            return str(file_path)
