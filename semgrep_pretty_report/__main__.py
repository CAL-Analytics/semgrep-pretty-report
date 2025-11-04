"""CLI interface for Semgrep Pretty Report."""

import sys
import json
import argparse
from pathlib import Path
from .semgrep_report import SemgrepReportGenerator


def main() -> None:
    """Generate beautiful HTML reports from Semgrep JSON output."""
    parser = argparse.ArgumentParser(
        description='Generate beautiful HTML reports from Semgrep JSON output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m semgrep_pretty_report results.json
  python -m semgrep_pretty_report results.json -o custom-report.html
  semgrep-pretty-report results.json --title "My Security Scan"
        """
    )

    parser.add_argument(
        'input_file',
        type=Path,
        help='Path to semgrep JSON results file'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=None,
        help='Output HTML file path (default: input_file.html)'
    )

    parser.add_argument(
        '--title',
        default='Semgrep Security Report',
        help='Report title (currently not used in template)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='semgrep-pretty-report 0.1.0'
    )

    args = parser.parse_args()

    # Determine output file path
    output_file = args.output
    if output_file is None:
        output_file = args.input_file.with_suffix('.html')

    # Validate input file exists and is readable JSON
    if not args.input_file.exists():
        print(f"Error: Input file '{args.input_file}' does not exist", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file '{args.input_file}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file '{args.input_file}': {e}", file=sys.stderr)
        sys.exit(1)

    # Generate report
    try:
        generator = SemgrepReportGenerator()
        generator.generate_report(args.input_file, output_file)
        print(f"✓ Report generated successfully: {output_file}")
        print(f"  Open in your browser: file://{output_file.absolute()}")
    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
