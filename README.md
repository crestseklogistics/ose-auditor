# OSE Auditor

**OSE Auditor** is an autonomous financial and logic exploit detection engine that uses deterministic code analysis and AI remediation to discover money‑losing vulnerabilities before deployment.

## Project Structure
ose-auditor/
├── client/ # Local CLI & parser (Open Source)
├── contracts/ # Data contract validation (Open Source)
├── fsa/ # Financial Semantic Analyzer (Proprietary)
├── server/ # Cloud API & billing (Proprietary)
├── tests/ # Unit and integration tests
└── docs/ # Documentation

text

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/crestsek/ose-auditor.git
cd ose-auditor
2. Create a virtual environment
bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
3. Install dependencies
bash
pip install -r requirements.txt
4. Set up environment variables
bash
cp .env.example .env
# Edit .env with your values
5. Run a local audit (with mock FSA)
bash
python -m client.ose audit /path/to/your/nodejs/project
Environment Variables
See .env.example for a complete list.

License
Proprietary. See LICENSE file for details.

text

---

## 5. `pyproject.toml` – FOR PACKAGING (Optional)

```toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "ose-auditor"
version = "1.0.0"
description = "Autonomous financial and logic exploit detection engine"
readme = "README.md"
requires-python = ">=3.10"
authors = [
    {name = "Crestsek Technology Ltd", email = "info@crestsek.com"}
]
classifiers = [
    "Programming Language :: Python :: 3",
    "License :: Other/Proprietary License",
]
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn>=0.30.0",
    "asyncpg>=0.29.0",
    "pydantic>=2.9.0",
    "httpx>=0.27.0",
    "python-dotenv>=1.0.0",
    "click>=8.1.0",
    "tree-sitter>=0.22.0",
    "tree-sitter-javascript>=0.20.0",
    "tree-sitter-typescript>=0.20.0",
]

[project.scripts]
ose = "client.ose:main"

[tool.setuptools.packages.find]
include = ["client*", "contracts*", "fsa*", "server*"]
exclude = ["tests*", "docs*"]

[tool.black]
line-length = 100
target-version = ['py310']

[tool.mypy]
python_version = "3.10"
ignore_missing_imports = true
