#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Horusec JSON to Markdown Converter

Author: Matheus Banhos
GitHub: https://github.com/matheusbanhos

This script converts Horusec JSON output to a formatted Markdown report.
"""

import sys
import json
import argparse
import logging
from datetime import datetime

# Configuração de logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configurações
SEVERITY_ICONS = {
    'CRITICAL': '🟣',
    'HIGH': '🔴',
    'MEDIUM': '🟠',
    'LOW': '🟢',
    'INFO': '🔵',
    'UNKNOWN': '⚪'
}


def read_horusec_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        return data
    except json.JSONDecodeError:
        logging.error(f"Erro ao decodificar o arquivo JSON: {file_path}")
        sys.exit(1)
    except IOError:
        logging.error(f"Erro ao ler o arquivo: {file_path}")
        sys.exit(1)


def clean_text(text):
    return text.replace('\n', ' ').replace('\r', ' ').replace('|', '\\|')


def severity_icon(severity):
    return SEVERITY_ICONS.get(severity.upper(), "⚪")


def format_date(date_string):
    try:
        date = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        return date.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return date_string


def validate_json_structure(data):
    required_keys = ['version', 'status', 'createdAt',
                     'finishedAt', 'analysisVulnerabilities']
    for key in required_keys:
        if key not in data:
            logging.error(f"Chave obrigatória ausente no JSON: {key}")
            return False
    return True


def write_markdown_report(data, output_file):
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(f"# Horusec {data.get('version', 'N/A')} Scan Report\n\n")
        file.write(f"**Status:** {data.get('status', 'N/A')}\n")
        file.write(
            f"**Created At:** {format_date(data.get('createdAt', 'N/A'))}\n")
        file.write(
            f"**Finished At:** {format_date(data.get('finishedAt', 'N/A'))}\n\n")

        file.write("## Vulnerabilities Summary\n\n")
        file.write("| Severity | Count |\n")
        file.write("|----------|------|\n")

        severity_count = {}
        for vuln in data.get('analysisVulnerabilities', []):
            severity = vuln.get('severity', 'UNKNOWN')
            severity_count[severity] = severity_count.get(severity, 0) + 1

        for severity, count in severity_count.items():
            file.write(f"| {severity_icon(severity)} {severity} | {count} |\n")

        file.write("\n## Vulnerabilities Details\n\n")
        file.write("| Severity | File | Line | Details |\n")
        file.write("|----------|------|------|--------|\n")

        for vuln in data.get('analysisVulnerabilities', []):
            severity = vuln.get('severity', 'UNKNOWN')
            vuln_file = clean_text(vuln.get('file', 'N/A'))
            line = vuln.get('line', 'N/A')
            details = clean_text(vuln.get('details', 'N/A'))

            file.write(f"| {severity_icon(severity)} {severity} | {
                       vuln_file} | {line} | {details} |\n")

        file.write("\n## Detailed Vulnerabilities\n\n")
        for i, vuln in enumerate(data.get('analysisVulnerabilities', []), 1):
            file.write(f"### {i}. {clean_text(
                vuln.get('details', 'N/A'))}\n\n")
            file.write(f"**Severity:** {severity_icon(vuln.get('severity', 'UNKNOWN'))} {
                       vuln.get('severity', 'UNKNOWN')}\n")
            file.write(f"**File:** {clean_text(vuln.get('file', 'N/A'))}\n")
            file.write(f"**Line:** {vuln.get('line', 'N/A')}\n")
            file.write(f"**Code:** `{clean_text(vuln.get('code', 'N/A'))}`\n")
            file.write(
                f"**Details:** {clean_text(vuln.get('details', 'N/A'))}\n")
            file.write(
                f"**Security Tool:** {vuln.get('securityTool', 'N/A')}\n")
            file.write(f"**Confidence:** {vuln.get('confidence', 'N/A')}\n\n")

    logging.info(f"Markdown report generated: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert Horusec JSON output to Markdown")
    parser.add_argument("input_file", help="Path to the Horusec JSON file")
    parser.add_argument("output_file", help="Path to save the Markdown report")
    args = parser.parse_args()

    data = read_horusec_json(args.input_file)

    if not validate_json_structure(data):
        logging.error("Invalid JSON structure. Exiting.")
        sys.exit(1)

    write_markdown_report(data, args.output_file)


if __name__ == "__main__":
    main()
