#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Horusec JSON to Markdown Converter

Author: Matheus Banhos
GitHub: https://github.com/matheusbanhos

This script converts Horusec JSON output to a formatted Markdown report.
"""

import sys
import codecs
import json
import argparse

# Tenta importar colorama para usar cores no terminal
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())


def read_horusec_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    return data


def clean_text(text):
    """Remoção de quebras de linha e caracteres especiais que possam comprometer a tabela."""
    return text.replace('\n', ' ').replace('\r', ' ').replace('|', ' ')


def clean_summary(summary):
    """Remove a frase inicial do sumário."""
    phrase = "(1/1) * Possible vulnerability detected: "
    if summary.startswith(phrase):
        return summary[len(phrase):]
    return summary

# def severity_icon(severity):
#     """Add severity icon based on severity level."""
#     icons = {
#         "CRITICAL": "🟣",
#         "HIGH": "🔴",
#         "MEDIUM": "🟡",
#         "LOW": "🟢",
#         "INFO": "🔵"
#     }
#     return icons.get(severity.upper(), "")


def severity_icon(severity):
    icons = {
        'CRITICAL': '\U0001F7E3',
        'HIGH': '\U0001F534',
        'MEDIUM': '\U0001F7E1',
        'LOW': '\U0001F7E2',
        'INFO': '\U0001F535',
    }
    return icons.get(severity.upper(), '')


def generate_markdown(data, output_path):
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(
            f"# Horusec {data.get('version', 'N/A')} - Static Application Security Test\n\n")
        # Table of contents
        file.write(
            "- [Horusec - Static Application Security Test](#horusec---static-application-security-test)\n\n")
        file.write("  - [Scan Info](#scan-info)\n\n")
        file.write(
            "  - [Tabela de Vulnerabilidades](#tabela-de-vulnerabilidades)\n\n")
        file.write(
            "  - [Descrição das Vulnerabilidades](#descrição-das-vulnerabilidades)\n\n")

        file.write("## Scan Info\n\n")
        file.write(f"**Version:** {data.get('version', 'N/A')}\n\n")
        file.write(f"**Status:** {data.get('status', 'N/A')}\n\n")
        file.write(f"**CreatedAt:** {data.get('createdAt', 'N/A')}\n\n")
        file.write(f"**FinishedAt:** {data.get('finishedAt', 'N/A')}\n\n")

        analysis_vulnerabilities = data.get('analysisVulnerabilities', [])

        if not analysis_vulnerabilities:
            file.write("Nenhuma vulnerabilidade encontrada.\n\n")
            if COLORAMA_AVAILABLE:
                print(Fore.GREEN + "Nenhuma vulnerabilidade encontrada.")
            else:
                print("Nenhuma vulnerabilidade encontrada.")
            return
        else:
            num_vulnerabilities = len(analysis_vulnerabilities)
            if COLORAMA_AVAILABLE:
                print(
                    Fore.RED + f"Vulnerabilidades encontradas: {num_vulnerabilities}.")
            else:
                print(f"Vulnerabilidades encontradas: {num_vulnerabilities}.")

        file.write("## Tabela de Vulnerabilidades\n\n")
        file.write(
            "| Severity | Rule ID | Sumário | Arquivo:Linha | Ferramenta de Segurança |\n")
        file.write("| --- | --- | --- | --- | --- |\n")

        for item in analysis_vulnerabilities:
            vulnerability = item.get('vulnerabilities', {})
            severity = vulnerability.get('severity', 'N/A').capitalize()
            icon = severity_icon(severity)
            rule_id = vulnerability.get('rule_id', 'N/A')
            details = vulnerability.get('details', 'N/A')
            summary = clean_text(details.split('\n', 1)[
                                 0] if '\n' in details else details)
            if len(summary) > 254:
                summary = f"{clean_summary(summary)[0:249]}..."
            else:
                summary = f"{clean_summary(summary)[0:249]}"
            file_line = f"{vulnerability.get(
                'file', 'N/A')}:{vulnerability.get('line', 'N/A')}"
            security_tool = vulnerability.get('securityTool', 'N/A')

            file.write(
                f"| {icon} {severity} | {rule_id} | {summary} | {file_line} | {security_tool} |\n")

        file.write("\n## Descrição das Vulnerabilidades\n\n")

        for item in data.get('analysisVulnerabilities', []):
            vulnerability = item.get('vulnerabilities', {})
            severity = vulnerability.get('severity', 'N/A').capitalize()
            icon = severity_icon(severity)
            details = vulnerability.get('details', 'N/A')

            # Split details into summary and description
            summary, description = details.split(
                '\n', 1) if '\n' in details else (details, '')
            summary = clean_summary(summary)
            if len(summary) > 254:
                summary_summary = f"{summary[0:100]}..."
            else:
                summary_summary = summary

            file_line = f"{vulnerability.get(
                'file', 'N/A')}:{vulnerability.get('line', 'N/A')}"
            code = vulnerability.get('code', 'N/A')
            security_tool = vulnerability.get('securityTool', 'N/A')

            file.write(f"### {icon} {summary_summary}\n\n")
            file.write(f"**Severidade:**  {icon} {severity}\n\n")
            file.write(f"**Sumário:** **{clean_text(summary)}**\n\n")
            file.write(f"**Descrição:** {description}\n\n")
            file.write(f"**Arquivo:** {file_line}\n\n")
            file.write(f"**Código:** `{code}`\n\n")
            file.write(f"**Ferramenta de Segurança:** {security_tool}\n\n")
            file.write("\n---\n\n")


def main():
    parser = argparse.ArgumentParser(
        description="Convert Horusec JSON to Markdown.")
    parser.add_argument("json_path", help="Path to the Horusec JSON file.")
    parser.add_argument(
        "markdown_path", help="Path to save the output Markdown file.")
    args = parser.parse_args()

    horusec_data = read_horusec_json(args.json_path)
    generate_markdown(horusec_data, args.markdown_path)


if __name__ == "__main__":
    main()

    # Adicionar esta verificação antes de chamar reset_all()
    if COLORAMA_AVAILABLE and not sys.stdout.closed:
        init(autoreset=True)
