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
import logging
from datetime import datetime

# Tenta importar colorama para usar cores no terminal
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

# Configuração de logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configurações
SEVERITY_ICONS = {
    'CRITICAL': '\U0001F7E3',
    'HIGH': '\U0001F534',
    'MEDIUM': '\U0001F7E1',
    'LOW': '\U0001F7E2',
    'INFO': '\U0001F535',
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
    return text.replace('\n', ' ').replace('\r', ' ').replace('|', ' ')


def clean_summary(summary):
    phrase = "(1/1) * Possible vulnerability detected: "
    return summary[len(phrase):] if summary.startswith(phrase) else summary


def severity_icon(severity):
    return SEVERITY_ICONS.get(severity.upper(), "")


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


def generate_markdown(data, output_path):
    if not validate_json_structure(data):
        sys.exit(1)

    try:
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write(f"# Horusec {data.get(
                'version', 'N/A')} - Static Application Security Test\n\n")
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
            file.write(
                f"**CreatedAt:** {format_date(data.get('createdAt', 'N/A'))}\n\n")
            file.write(
                f"**FinishedAt:** {format_date(data.get('finishedAt', 'N/A'))}\n\n")

            analysis_vulnerabilities = data.get('analysisVulnerabilities', [])

            if not analysis_vulnerabilities:
                file.write("Nenhuma vulnerabilidade encontrada.\n\n")
                logging.info("Nenhuma vulnerabilidade encontrada.")
                return
            else:
                num_vulnerabilities = len(analysis_vulnerabilities)
                logging.warning(f"Vulnerabilidades encontradas: {
                                num_vulnerabilities}.")

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
                summary = f"{clean_summary(summary)[0:249]}..." if len(
                    summary) > 254 else f"{clean_summary(summary)[0:249]}"
                file_line = f"{vulnerability.get(
                    'file', 'N/A')}:{vulnerability.get('line', 'N/A')}"
                security_tool = vulnerability.get('securityTool', 'N/A')

                file.write(f"| {icon} {severity} | {rule_id} | {
                           summary} | {file_line} | {security_tool} |\n")

            file.write("\n## Descrição das Vulnerabilidades\n\n")

            for item in data.get('analysisVulnerabilities', []):
                vulnerability = item.get('vulnerabilities', {})
                severity = vulnerability.get('severity', 'N/A').capitalize()
                icon = severity_icon(severity)
                details = vulnerability.get('details', 'N/A')

                summary, description = details.split(
                    '\n', 1) if '\n' in details else (details, '')
                summary = clean_summary(summary)
                summary_summary = f"{summary[0:100]}..." if len(
                    summary) > 254 else summary

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

    except IOError:
        logging.error(f"Erro ao escrever no arquivo de saída: {output_path}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Convert Horusec JSON to Markdown.")
    parser.add_argument("json_path", help="Path to the Horusec JSON file.")
    parser.add_argument(
        "markdown_path", help="Path to save the output Markdown file.")
    parser.add_argument("--color", action="store_true",
                        help="Enable colored output in terminal")
    args = parser.parse_args()

    if args.color and COLORAMA_AVAILABLE:
        init(autoreset=True)

    horusec_data = read_horusec_json(args.json_path)
    generate_markdown(horusec_data, args.markdown_path)


if __name__ == "__main__":
    main()
