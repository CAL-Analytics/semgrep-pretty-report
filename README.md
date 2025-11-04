# Semgrep Pretty Report

[![PyPI version](https://badge.fury.io/py/semgrep-pretty-report.svg)](https://pypi.org/project/semgrep-pretty-report/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A beautiful, self-contained HTML report generator for [Semgrep](https://semgrep.dev/) security scan results. Perfect for CI/CD pipelines where you need to share security findings as artifacts.

[![View Sample Report](https://img.shields.io/badge/View-Sample_Report-blue)](sample-report.html)
[![Download Sample JSON](https://img.shields.io/badge/Download-Sample_Data-green)](semgrep-report-sample.json)

## ✨ Features

- **Self-contained HTML**: All CSS, JavaScript, and charts embedded - no external dependencies
- **Interactive filtering**: Filter by severity, category, file path, and search terms
- **Detailed views**: Click "Details" on any finding for comprehensive information
- **Beautiful charts**: Base64-embedded severity distribution charts (when matplotlib available)
- **Beautiful design**: Modern, responsive UI with severity-based color coding
- **CI/CD ready**: Perfect for pipeline artifacts and web-based viewing
- **Fast generation**: Process large semgrep outputs quickly
- **Rich metadata**: Displays CWE, OWASP, technology tags, and references
- **Source code display**: Shows actual code snippets from your files (when available)

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI
pip install semgrep-pretty-report

# Or install from source
git clone https://github.com/calanalytics/semgrep-pretty-report.git
cd semgrep-pretty-report
pip install .
```

### Usage

```bash
# Basic usage - generates results.html
semgrep-pretty-report results.json

# Custom output file
semgrep-pretty-report results.json -o my-security-report.html

# With custom title
semgrep-pretty-report results.json --title "My Project Security Scan"

# Get help
semgrep-pretty-report --help
```

### Try It Out

Want to see it in action? Try the included sample data:

```bash
# Generate the sample report
semgrep-pretty-report semgrep-report-sample.json -o my-sample-report.html

# Open in your browser
open my-sample-report.html
```

The sample includes:
- **8 security findings** across different severity levels (ERROR, WARNING)
- **3 scan errors** demonstrating error handling
- **Real semgrep output structure** with all metadata intact
- **Sanitized data** - no real company information included

### CI/CD Integration

#### GitHub Actions
```yaml
- name: Run Semgrep
  run: semgrep ci --json > semgrep-results.json

- name: Generate HTML Report
  run: semgrep-pretty-report semgrep-results.json -o security-report.html

- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: security-report
    path: security-report.html
```

#### GitLab CI
```yaml
semgrep:
  script:
    - semgrep ci --json > semgrep-results.json
    - semgrep-pretty-report semgrep-results.json -o security-report.html
  artifacts:
    paths:
      - security-report.html
    expire_in: 1 week
```

#### Jenkins
```groovy
pipeline {
    stages {
        stage('Security Scan') {
            steps {
                sh 'semgrep ci --json > semgrep-results.json'
                sh 'semgrep-pretty-report semgrep-results.json -o security-report.html'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'security-report.html', fingerprint: true
        }
    }
}
```

## 📊 Report Features

### Summary Dashboard
- Total findings count with severity breakdown
- Files scanned vs files affected
- Top security issues
- Category distribution

### Interactive Table
- Sortable columns
- Real-time filtering by:
  - Severity (Error, Warning, Info)
  - Category (security, audit, etc.)
  - File path patterns
  - Free text search in messages and check IDs

### Detailed Findings View
Click "Details" on any finding to see:
- Full check ID and message
- File location with line numbers
- Severity and confidence levels
- Technology and category tags
- CWE and OWASP classifications
- **Actual source code snippets** from your files (with line numbers)
- External references and links

### Error Reporting
- Scan errors and syntax issues are clearly displayed
- Separate section for troubleshooting

## 🛠️ Development

### Setup
```bash
# Clone repository
git clone https://github.com/calanalytics/semgrep-pretty-report.git
cd semgrep-pretty-report

# Install dependencies
poetry install

# Run tests
poetry run pytest

# Build package
poetry build
```

### Project Structure
```
semgrep-pretty-report/
├── semgrep_pretty_report/
│   ├── __init__.py
│   ├── __main__.py          # CLI interface
│   └── semgrep_report.py    # Core HTML generation logic
├── semgrep-report-sample.json  # Sample semgrep output (sanitized)
├── sample-report.html          # Generated sample report
├── tests/
├── pyproject.toml
└── README.md
```

### Adding New Features
The HTML template is embedded in `semgrep_report.py`. To modify the report appearance:

1. Edit the `_get_template_html()` method
2. Use Jinja2 templating for dynamic content
3. Keep all CSS/JS inline for self-containment
4. Test with the included sample: `semgrep-report-sample.json`

## 📋 Requirements

- Python 3.11+
- Semgrep JSON output file
- **Optional**: matplotlib + numpy for embedded charts (otherwise shows text fallback)

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Semgrep](https://semgrep.dev/) for the amazing security scanner
- Inspired by the need for better CI/CD security reporting
- Built with modern web standards for maximum compatibility

## 🐛 Issues & Support

- [GitHub Issues](https://github.com/calanalytics/semgrep-pretty-report/issues)
- For questions: [Discussions](https://github.com/calanalytics/semgrep-pretty-report/discussions)

---

**Made with ❤️ for the security community**
