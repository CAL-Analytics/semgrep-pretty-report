"""Semgrep HTML Report Generator."""

import json
import base64
import io
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class Finding:
    """Represents a single semgrep finding."""

    check_id: str
    path: str
    start_line: int
    end_line: int
    severity: str
    confidence: str
    message: str
    category: str
    technology: List[str] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    shortlink: Optional[str] = None
    lines: Optional[str] = None
    fingerprint: Optional[str] = None

    @property
    def severity_order(self) -> int:
        """Return severity order for sorting."""
        order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        return order.get(self.severity, 3)

    @property
    def confidence_order(self) -> int:
        """Return confidence order for sorting."""
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        return order.get(self.confidence, 3)


@dataclass
class SemgrepReport:
    """Represents a complete semgrep report."""

    version: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    scanned_paths: List[str] = field(default_factory=list)
    total_files_scanned: int = 0
    scan_time: Optional[Dict[str, Any]] = None

    @property
    def summary_stats(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        severity_counts = Counter(f.severity for f in self.findings)
        confidence_counts = Counter(f.confidence for f in self.findings)
        category_counts = Counter(f.category for f in self.findings)

        # Group findings by file
        files_affected = len(set(f.path for f in self.findings))

        # Most common issues
        check_id_counts = Counter(f.check_id for f in self.findings)
        top_issues = check_id_counts.most_common(5)

        return {
            "total_findings": len(self.findings),
            "total_errors": len(self.errors),
            "files_scanned": self.total_files_scanned,
            "files_affected": files_affected,
            "severity_breakdown": dict(severity_counts),
            "confidence_breakdown": dict(confidence_counts),
            "category_breakdown": dict(category_counts),
            "top_issues": top_issues,
        }


class SemgrepReportGenerator:
    """Generates HTML reports from semgrep JSON output."""

    def __init__(self):
        self.template = self._get_html_template()

    def generate_report(self, json_file: Path, output_file: Path) -> None:
        """Generate HTML report from semgrep JSON file."""
        # Load and parse JSON
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Parse report data
        report = self._parse_semgrep_data(data)

        # Generate HTML
        html_content = self._generate_html(report)

        # Write output
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"Report generated: {output_file}")

    def _parse_semgrep_data(self, data: Dict[str, Any]) -> SemgrepReport:
        """Parse semgrep JSON data into our report structure."""
        report = SemgrepReport(
            version=data.get("version", "unknown"),
            errors=data.get("errors", []),
            scanned_paths=data.get("paths", {}).get("scanned", []),
            total_files_scanned=len(data.get("paths", {}).get("scanned", [])),
            scan_time=data.get("time", {})
        )

        # Parse findings
        for result in data.get("results", []):
            finding = self._parse_finding(result)
            report.findings.append(finding)

        # Sort findings by severity then file
        report.findings.sort(key=lambda f: (f.severity_order, f.path, f.start_line))

        return report

    def _parse_finding(self, result: Dict[str, Any]) -> Finding:
        """Parse a single semgrep result into a Finding object."""
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        return Finding(
            check_id=result["check_id"],
            path=result["path"],
            start_line=result["start"]["line"],
            end_line=result["end"]["line"],
            severity=extra.get("severity", "UNKNOWN"),
            confidence=metadata.get("confidence", "UNKNOWN"),
            message=extra["message"],
            category=metadata.get("category", "unknown"),
            technology=metadata.get("technology", []),
            cwe=metadata.get("cwe", []),
            owasp=metadata.get("owasp", []),
            references=metadata.get("references", []),
            shortlink=metadata.get("shortlink"),
            lines=extra.get("lines"),
            fingerprint=extra.get("fingerprint")
        )

    def _generate_html(self, report: SemgrepReport) -> str:
        """Generate HTML content from report data."""
        stats = report.summary_stats

        # Prepare data for template
        template_data = {
            "report": report,
            "stats": stats,
            "findings_json": json.dumps([{
                "check_id": f.check_id,
                "path": f.path,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "severity": f.severity,
                "confidence": f.confidence,
                "message": f.message,
                "category": f.category,
                "technology": f.technology,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "references": f.references,
                "shortlink": f.shortlink,
                "lines": f.lines,
                "fingerprint": f.fingerprint,
            } for f in report.findings]),
            "errors_json": json.dumps(report.errors),
            "generated_at": datetime.now().isoformat(),
        }

        # Get template and do basic string replacement
        template = self._get_template_html()

        # Replace template variables
        html = template
        html = html.replace("{{ findings_json|safe }}", template_data["findings_json"])
        html = html.replace("{{ errors_json|safe }}", template_data["errors_json"])
        html = html.replace("{{ generated_at[:19].replace('T', ' ') }}", template_data["generated_at"][:19].replace('T', ' '))
        html = html.replace("{{ stats.total_findings }}", str(stats["total_findings"]))
        html = html.replace("{{ stats.files_scanned }}", str(stats["files_scanned"]))
        html = html.replace("{{ stats.files_affected }}", str(stats["files_affected"]))
        html = html.replace("{{ stats.severity_breakdown.get('ERROR', 0) }}", str(stats["severity_breakdown"].get('ERROR', 0)))
        html = html.replace("{{ stats.severity_breakdown.get('WARNING', 0) }}", str(stats["severity_breakdown"].get('WARNING', 0)))
        html = html.replace("{{ stats.severity_breakdown.get('INFO', 0) }}", str(stats["severity_breakdown"].get('INFO', 0)))
        html = html.replace("{{ report.errors|length }}", str(len(report.errors)))
        html = html.replace("{{ report.version }}", report.version)

        # Replace category options
        category_options = ""
        for category in stats["category_breakdown"].keys():
            category_options += f'                        <option value="{category}">{category.title()}</option>'
        html = html.replace("""                        {% for category in stats.category_breakdown.keys() %}
                        <option value="{{ category }}">{{ category.title() }}</option>
                        {% endfor %}""", category_options)

        # Handle errors section
        if report.errors:
            # Build the errors table HTML
            errors_rows = ""
            for error in report.errors:
                error_type = error.get('type', 'Unknown')
                error_path = error.get('path', 'Unknown')
                error_message = error.get('message', 'Unknown')
                errors_rows += f"""
                    <tr>
                        <td>{error_type}</td>
                        <td class="file-path">{error_path}</td>
                        <td>{error_message}</td>
                    </tr>"""

            # Replace the template markers with actual content
            html = html.replace("{% if report.errors %}", "")
            html = html.replace("{% endif %}", "")
            html = html.replace("{% for error in report.errors %}", "")
            html = html.replace("{% endfor %}", "")
            html = html.replace("{{ report.errors|length }}", str(len(report.errors)))

            # Replace the template table row with actual error rows
            html = html.replace("""                    <tr>
                        <td>{{ error.type }}</td>
                        <td class="file-path">{{ error.path }}</td>
                        <td>{{ error.message }}</td>
                    </tr>""", errors_rows)
        else:
            # Remove the entire error section
            html = html.replace("{% if report.errors %}", "")
            html = html.replace("{% endif %}", "")
            html = html.replace("{% for error in report.errors %}", "")
            html = html.replace("{% endfor %}", "")

        # Generate severity chart
        chart_base64 = self._generate_severity_chart(stats["severity_breakdown"])

        # Replace chart placeholder
        if chart_base64:
            chart_html = f'<img src="{chart_base64}" alt="Severity Distribution Chart">'
            html = html.replace("Interactive charts would be displayed here", chart_html)
        else:
            html = html.replace("Interactive charts would be displayed here", "Chart generation requires matplotlib")

        return html

    def _generate_severity_chart(self, severity_breakdown: Dict[str, int]) -> str:
        """Generate a base64 encoded severity distribution chart."""
        try:
            import matplotlib.pyplot as plt
            import matplotlib
            matplotlib.use('Agg')  # Use non-interactive backend

            # Prepare data
            severities = ['ERROR', 'WARNING', 'INFO']
            counts = [severity_breakdown.get(sev, 0) for sev in severities]
            colors = ['#e74c3c', '#f39c12', '#3498db']  # Red, Orange, Blue

            # Create figure with wider rectangle for better container fit
            fig, ax = plt.subplots(figsize=(16, 6), dpi=120, facecolor='#2c3e50')
            ax.set_facecolor('#34495e')

            # Create bars with better proportions for wider chart
            bars = ax.bar(severities, counts, color=colors, alpha=0.9, edgecolor='white', linewidth=2, width=0.8)

            # Add value labels on bars with better positioning
            max_count = max(counts) if counts else 1
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                if height > 0:
                    # Position label above the bar with some margin
                    label_y = height + max_count * 0.05
                    ax.text(bar.get_x() + bar.get_width()/2., label_y,
                           f'{int(count)}', ha='center', va='bottom',
                           fontsize=14, fontweight='bold', color='white')

            # Enhanced styling for web display
            ax.set_title('Security Findings by Severity', fontsize=18, fontweight='bold',
                        color='white', pad=25, loc='center')
            ax.set_ylabel('Number of Findings', fontsize=14, color='white', labelpad=15)
            ax.tick_params(axis='x', colors='white', labelsize=13, pad=10)
            ax.tick_params(axis='y', colors='white', labelsize=12, pad=5)

            # Remove main grid lines, add subtle horizontal lines only
            ax.grid(False)
            ax.yaxis.grid(True, alpha=0.2, color='white', linestyle='--')

            # Set y-axis to start from 0 and add some top margin
            ax.set_ylim(0, max_count * 1.15 if max_count > 0 else 5)

            # Ensure proper spacing and layout
            plt.tight_layout()

            # Convert to base64 with high quality
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=120, bbox_inches='tight',
                       facecolor='#2c3e50', edgecolor='none', pad_inches=0.2)
            plt.close(fig)
            buffer.seek(0)

            image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            return f"data:image/png;base64,{image_base64}"

        except ImportError:
            # Fallback if matplotlib is not available
            return ""
        except Exception as e:
            print(f"Warning: Could not generate chart: {e}")
            return ""

    def _get_html_template(self) -> str:
        """Get the HTML template string."""
        return self._get_template_html()

    def _get_template_html(self) -> str:
        """Return the complete HTML template with inline CSS and JS."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Semgrep Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }

        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            text-align: center;
            transition: transform 0.2s ease;
        }

        .stat-card:hover {
            transform: translateY(-2px);
        }

        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .stat-label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .severity-error { color: #e74c3c; }
        .severity-warning { color: #f39c12; }
        .severity-info { color: #3498db; }

        .filters {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }

        .filter-row {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            min-width: 150px;
        }

        .filter-label {
            font-size: 0.85em;
            color: #666;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        select, input[type="text"] {
            padding: 8px 12px;
            border: 2px solid #e1e8ed;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.2s ease;
        }

        select:focus, input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }

        .findings-table {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            margin-bottom: 20px;
        }

        .table-responsive {
            position: relative;
        }

        .table-responsive::after {
            content: "";
            position: absolute;
            top: 0;
            right: 0;
            width: 20px;
            height: 100%;
            background: linear-gradient(to left, rgba(255,255,255,0.9), transparent);
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.3s;
        }

        .table-responsive.has-scroll::after {
            opacity: 1;
        }

        .table-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e1e8ed;
        }

        .table-header h3 {
            color: #333;
            margin-bottom: 10px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e1e8ed;
        }

        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #555;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-error-badge { background: #fee; color: #e74c3c; border: 1px solid #fcc; }
        .severity-warning-badge { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .severity-info-badge { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }

        .file-path {
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.85em;
            color: #666;
        }

        .line-number {
            color: #999;
            font-size: 0.8em;
        }

        .message-cell {
            max-width: 400px;
        }

        .message-text {
            display: block;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .message-text:hover {
            white-space: normal;
        }

        .expand-btn {
            background: none;
            border: none;
            color: #667eea;
            cursor: pointer;
            font-size: 0.8em;
            padding: 2px 6px;
            border-radius: 3px;
            margin-left: 5px;
        }

        .expand-btn:hover {
            background: #f0f2ff;
        }

        .details-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            padding: 20px;
        }

        .modal-content {
            background: white;
            max-width: 800px;
            margin: 0 auto;
            border-radius: 12px;
            max-height: 90vh;
            overflow-y: auto;
            position: relative;
        }

        .modal-header {
            padding: 20px;
            border-bottom: 1px solid #e1e8ed;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-body {
            padding: 20px;
        }

        .close-btn {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #666;
        }

        .close-btn:hover {
            color: #333;
        }

        .detail-section {
            margin-bottom: 20px;
        }

        .detail-label {
            font-weight: 600;
            color: #555;
            margin-bottom: 5px;
        }

        .detail-value {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 6px;
            font-family: monospace;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .code-block {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', monospace;
            overflow-x: auto;
            white-space: pre;
        }

        .tag-list {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
        }

        .tag {
            background: #e1e8ed;
            color: #555;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.75em;
        }

        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            overflow: hidden; /* Ensure content doesn't overflow */
        }

        .chart-header {
            margin-bottom: 15px;
            text-align: center;
        }

        .chart-placeholder {
            height: 300px;
            background: #f8f9fa;
            border: 2px dashed #dee2e6;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #6c757d;
            font-size: 1.1em;
        }

        .chart-container img {
            width: 90%;
            height: auto;
            max-width: 700px;
            max-height: 300px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: block;
            margin: 0 auto;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }

            @media (max-width: 768px) {
                .container {
                    padding: 10px;
                }

                .header {
                    padding: 15px;
                    margin-bottom: 20px;
                }

                .header h1 {
                    font-size: 1.8em;
                    margin-bottom: 8px;
                }

                .header p {
                    font-size: 1em;
                }

                .stats-grid {
                    grid-template-columns: 1fr;
                    gap: 15px;
                }

                .stat-card {
                    padding: 20px 15px;
                }

                .chart-container {
                    padding: 15px;
                    margin-bottom: 15px;
                }

                .chart-container img {
                    width: 90%;
                    height: auto;
                    max-width: 700px;
                    max-height: 300px;
                }

                .filter-row {
                    flex-direction: column;
                    gap: 10px;
                }

                .filter-group {
                    min-width: auto;
                    width: 100%;
                }

            .table-responsive {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
            }

                .findings-table {
                    margin-bottom: 15px;
                    font-size: 0.9em;
                }

                .table-header h3 {
                    font-size: 1.1em;
                }

                th, td {
                    padding: 8px 6px;
                    font-size: 0.85em;
                    white-space: nowrap;
                }

                th:nth-child(5), td:nth-child(5) { /* Check ID column */
                    max-width: 120px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }

                th:nth-child(6), td:nth-child(6) { /* Message column */
                    max-width: 200px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: normal;
                }

                .footer {
                    padding: 15px;
                    font-size: 0.85em;
                }
            }

            @media (max-width: 480px) {
                .container {
                    padding: 8px;
                }

                .header {
                    padding: 12px;
                    text-align: center;
                }

                .header h1 {
                    font-size: 1.5em;
                }

                .stat-card {
                    padding: 15px 10px;
                }

                .stat-number {
                    font-size: 2.5em;
                }

                .chart-container {
                    padding: 10px;
                }

                .chart-header h3 {
                    font-size: 1.1em;
                }

                .filters {
                    padding: 15px;
                }

                .filter-label {
                    font-size: 0.8em;
                }

                select, input[type="text"] {
                    font-size: 14px;
                    padding: 6px 10px;
                }

                /* Hide less important columns on very small screens */
                th:nth-child(2), td:nth-child(2), /* Category */
                th:nth-child(5), td:nth-child(5) { /* Check ID */
                    display: none;
                }

                th:nth-child(6), td:nth-child(6) { /* Message */
                    max-width: 150px;
                }

                /* Make severity badges smaller */
                .severity-badge {
                    font-size: 0.7em;
                    padding: 2px 4px;
                }

                /* Make table even more compact */
                th, td {
                    padding: 6px 4px;
                    font-size: 0.8em;
                }
            }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Semgrep Security Report</h1>
            <p>Generated on {{ generated_at[:19].replace('T', ' ') }}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number severity-error">{{ stats.total_findings }}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.files_scanned }}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.files_affected }}</div>
                <div class="stat-label">Files Affected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number severity-error">{{ stats.severity_breakdown.get('ERROR', 0) }}</div>
                <div class="stat-label">Errors</div>
            </div>
            <div class="stat-card">
                <div class="stat-number severity-warning">{{ stats.severity_breakdown.get('WARNING', 0) }}</div>
                <div class="stat-label">Warnings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number severity-info">{{ stats.severity_breakdown.get('INFO', 0) }}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>

        <div class="chart-container">
            <div class="chart-header">
                <h3>Severity Distribution</h3>
            </div>
            <div class="chart-placeholder">
                Interactive charts would be displayed here
            </div>
        </div>

        <div class="filters">
            <div class="filter-row">
                <div class="filter-group">
                    <label class="filter-label">Severity</label>
                    <select id="severity-filter">
                        <option value="">All Severities</option>
                        <option value="ERROR">Error</option>
                        <option value="WARNING">Warning</option>
                        <option value="INFO">Info</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label class="filter-label">Category</label>
                    <select id="category-filter">
                        <option value="">All Categories</option>
                        {% for category in stats.category_breakdown.keys() %}
                        <option value="{{ category }}">{{ category.title() }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="filter-group">
                    <label class="filter-label">Search</label>
                    <input type="text" id="search-filter" placeholder="Search findings...">
                </div>
                <div class="filter-group">
                    <label class="filter-label">File Path</label>
                    <input type="text" id="file-filter" placeholder="Filter by file path...">
                </div>
            </div>
        </div>

        <div class="findings-table">
            <div class="table-header">
                <h3>Findings ({{ stats.total_findings }})</h3>
            </div>
            <div class="table-responsive">
                <table id="findings-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Check ID</th>
                            <th>Message</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="findings-body">
                        <!-- Findings will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>

        {% if report.errors %}
        <div class="findings-table">
            <div class="table-header">
                <h3>Scan Errors ({{ report.errors|length }})</h3>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Path</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    {% for error in report.errors %}
                    <tr>
                        <td>{{ error.type }}</td>
                        <td class="file-path">{{ error.path }}</td>
                        <td>{{ error.message }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
    </div>

    <!-- Modal for detailed view -->
    <div id="details-modal" class="details-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Finding Details</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="modal-body">
                <!-- Details will be populated by JavaScript -->
            </div>
        </div>
    </div>

    <div class="footer">
        <p>Report generated by Semgrep Pretty Report v{{ report.version }} | Semgrep version: {{ report.version }}</p>
    </div>

    <script>
        // Data from Python
        const findings = {{ findings_json|safe }};
        const errors = {{ errors_json|safe }};

        // DOM elements
        const severityFilter = document.getElementById('severity-filter');
        const categoryFilter = document.getElementById('category-filter');
        const searchFilter = document.getElementById('search-filter');
        const fileFilter = document.getElementById('file-filter');
        const findingsBody = document.getElementById('findings-body');
        const modal = document.getElementById('details-modal');
        const modalBody = document.getElementById('modal-body');

            // Initialize
            document.addEventListener('DOMContentLoaded', function() {
                renderFindings(findings);
                setupFilters();
                setupResponsiveTable();
            });

            function setupResponsiveTable() {
                const tableResponsive = document.querySelector('.table-responsive');
                const table = document.querySelector('table');

                function checkScroll() {
                    if (table && table.offsetWidth > tableResponsive.offsetWidth) {
                        tableResponsive.classList.add('has-scroll');
                    } else {
                        tableResponsive.classList.remove('has-scroll');
                    }
                }

                // Check on load and resize
                checkScroll();
                window.addEventListener('resize', checkScroll);
            }

        function setupFilters() {
            severityFilter.addEventListener('change', filterFindings);
            categoryFilter.addEventListener('change', filterFindings);
            searchFilter.addEventListener('input', filterFindings);
            fileFilter.addEventListener('input', filterFindings);
        }

        function filterFindings() {
            const severity = severityFilter.value;
            const category = categoryFilter.value;
            const search = searchFilter.value.toLowerCase();
            const fileSearch = fileFilter.value.toLowerCase();

            const filtered = findings.filter(finding => {
                if (severity && finding.severity !== severity) return false;
                if (category && finding.category !== category) return false;
                if (search && !finding.message.toLowerCase().includes(search) &&
                    !finding.check_id.toLowerCase().includes(search)) return false;
                if (fileSearch && !finding.path.toLowerCase().includes(fileSearch)) return false;
                return true;
            });

            renderFindings(filtered);
        }

        function renderFindings(findingsList) {
            findingsBody.innerHTML = '';

            findingsList.forEach((finding, index) => {
                const row = document.createElement('tr');

                row.innerHTML = `
                    <td><span class="severity-badge severity-${finding.severity.toLowerCase()}-badge">${finding.severity}</span></td>
                    <td>${finding.category}</td>
                    <td class="file-path">${finding.path}</td>
                    <td class="line-number">${finding.start_line}</td>
                    <td>${finding.check_id.split('.').pop()}</td>
                    <td class="message-cell">
                        <span class="message-text">${finding.message}</span>
                    </td>
                    <td>
                        <button class="expand-btn" onclick="showDetails(${index})">Details</button>
                    </td>
                `;

                findingsBody.appendChild(row);
            });
        }

        function showDetails(index) {
            const finding = findings[index];

            let detailsHtml = `
                <div class="detail-section">
                    <div class="detail-label">Check ID</div>
                    <div class="detail-value">${finding.check_id}</div>
                </div>

                <div class="detail-section">
                    <div class="detail-label">Message</div>
                    <div class="detail-value">${finding.message}</div>
                </div>

                <div class="detail-section">
                    <div class="detail-label">File & Location</div>
                    <div class="detail-value">${finding.path}:${finding.start_line}-${finding.end_line}</div>
                </div>

                <div class="detail-section">
                    <div class="detail-label">Severity & Confidence</div>
                    <div class="detail-value">${finding.severity} / ${finding.confidence}</div>
                </div>

                <div class="detail-section">
                    <div class="detail-label">Category</div>
                    <div class="detail-value">${finding.category}</div>
                </div>
            `;

            if (finding.technology && finding.technology.length > 0) {
                detailsHtml += `
                    <div class="detail-section">
                        <div class="detail-label">Technology</div>
                        <div class="detail-value">
                            <div class="tag-list">
                                ${finding.technology.map(tech => `<span class="tag">${tech}</span>`).join('')}
                            </div>
                        </div>
                    </div>
                `;
            }

            if (finding.cwe && finding.cwe.length > 0) {
                detailsHtml += `
                    <div class="detail-section">
                        <div class="detail-label">CWE</div>
                        <div class="detail-value">
                            <div class="tag-list">
                                ${finding.cwe.map(cwe => `<span class="tag">${cwe}</span>`).join('')}
                            </div>
                        </div>
                    </div>
                `;
            }

            if (finding.owasp && finding.owasp.length > 0) {
                detailsHtml += `
                    <div class="detail-section">
                        <div class="detail-label">OWASP</div>
                        <div class="detail-value">
                            <div class="tag-list">
                                ${finding.owasp.map(owasp => `<span class="tag">${owasp}</span>`).join('')}
                            </div>
                        </div>
                    </div>
                `;
            }

            if (finding.lines) {
                detailsHtml += `
                    <div class="detail-section">
                        <div class="detail-label">Code Lines</div>
                        <div class="detail-value">
                            <div class="code-block">${finding.lines}</div>
                        </div>
                    </div>
                `;
            }

            if (finding.references && finding.references.length > 0) {
                detailsHtml += `
                    <div class="detail-section">
                        <div class="detail-label">References</div>
                        <div class="detail-value">
                            <ul>
                                ${finding.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `;
            }

            if (finding.shortlink) {
                detailsHtml += `
                    <div class="detail-section">
                        <div class="detail-label">Semgrep Link</div>
                        <div class="detail-value">
                            <a href="${finding.shortlink}" target="_blank">${finding.shortlink}</a>
                        </div>
                    </div>
                `;
            }

            modalBody.innerHTML = detailsHtml;
            modal.style.display = 'block';
        }

        function closeModal() {
            modal.style.display = 'none';
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            if (event.target === modal) {
                closeModal();
            }
        }
    </script>
</body>
</html>"""
