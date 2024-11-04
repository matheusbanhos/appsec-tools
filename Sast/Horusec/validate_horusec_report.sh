#!/bin/bash

# Configurações
REPORT_FILE="reports/horusec_report.json"

# Lista de bypass baseada em rule_id
BYPASS_RULE_ID_LIST=(
  "HS-LEAKS-25"
)

# Lista de bypass baseada em vulnerabilityID
BYPASS_VULNERABILITY_ID_LIST=(
  "c2427f29-2f94-47de-b84d-e08f15b139f4"
)

# Função para imprimir tabela
imprimir_tabela() {
  local criticas=$1
  local altas=$2
  local medias=$3
  local baixas=$4

  echo "+-----------+-------------+"
  echo "| Severidade| Quantidade  |"
  echo "+-----------+-------------+"
  printf "| Crítica   | %-11d |\n" $criticas
  printf "| Alta      | %-11d |\n" $altas
  printf "| Média     | %-11d |\n" $medias
  printf "| Baixa     | %-11d |\n" $baixas
  echo "+-----------+-------------+"
}

# Verificar se o arquivo de relatório existe
if [ ! -f "$REPORT_FILE" ]; then
  echo "Arquivo de relatório JSON do Horusec não encontrado. É possível que o Horusec não tenha sido executado corretamente."
  exit 1
fi

# Validar a estrutura básica do JSON
if ! jq empty "$REPORT_FILE" 2>/dev/null; then
  echo "Formato JSON inválido em $REPORT_FILE"
  exit 1
fi

# Verificar campos essenciais
CAMPOS_OBRIGATORIOS=("version" "id" "status" "createdAt" "finishedAt" "analysisVulnerabilities")
for campo in "${CAMPOS_OBRIGATORIOS[@]}"; do
  if ! jq -e ".$campo" "$REPORT_FILE" > /dev/null; then
    echo "Campo obrigatório ausente: $campo"
    exit 1
  fi
done

# Converter as listas de bypass para formato JSON
BYPASS_RULE_ID_JSON=$(printf '%s\n' "${BYPASS_RULE_ID_LIST[@]}" | jq -R . | jq -s .)
BYPASS_VULNERABILITY_ID_JSON=$(printf '%s\n' "${BYPASS_VULNERABILITY_ID_LIST[@]}" | jq -R . | jq -s .)

# Contar vulnerabilidades por severidade
CRITICAS=$(jq '[.analysisVulnerabilities[] | select(.vulnerabilities.severity == "CRITICAL")] | length' "$REPORT_FILE")
ALTAS=$(jq '[.analysisVulnerabilities[] | select(.vulnerabilities.severity == "HIGH")] | length' "$REPORT_FILE")
MEDIAS=$(jq '[.analysisVulnerabilities[] | select(.vulnerabilities.severity == "MEDIUM")] | length' "$REPORT_FILE")
BAIXAS=$(jq '[.analysisVulnerabilities[] | select(.vulnerabilities.severity == "LOW")] | length' "$REPORT_FILE")

# Imprimir tabela de vulnerabilidades
echo "Resumo de Vulnerabilidades Encontradas:"
imprimir_tabela $CRITICAS $ALTAS $MEDIAS $BAIXAS

# Verificar vulnerabilidades críticas e altas não bypassed
CRITICAS_NAO_BYPASSED=$(jq --argjson bypass_rule "$BYPASS_RULE_ID_JSON" --argjson bypass_vuln "$BYPASS_VULNERABILITY_ID_JSON" '
  [.analysisVulnerabilities[] | 
   select(.vulnerabilities.severity == "CRITICAL") | 
   select(
     (.vulnerabilities.rule_id | . as $item | $bypass_rule | index($item) | not) and
     (.vulnerabilities.vulnerabilityID | . as $item | $bypass_vuln | index($item) | not)
   )] | 
  length' "$REPORT_FILE")

ALTAS_NAO_BYPASSED=$(jq --argjson bypass_rule "$BYPASS_RULE_ID_JSON" --argjson bypass_vuln "$BYPASS_VULNERABILITY_ID_JSON" '
  [.analysisVulnerabilities[] | 
   select(.vulnerabilities.severity == "HIGH") | 
   select(
     (.vulnerabilities.rule_id | . as $item | $bypass_rule | index($item) | not) and
     (.vulnerabilities.vulnerabilityID | . as $item | $bypass_vuln | index($item) | not)
   )] | 
  length' "$REPORT_FILE")

echo ""
echo "Análise de Vulnerabilidades:"

if [ "$CRITICAS_NAO_BYPASSED" -gt 0 ]; then
  echo "$CRITICAS_NAO_BYPASSED - Crítica(s) - A pipeline não pode prosseguir. Precisamos da sua correção dessas vulnerabilidades críticas para manter a empresa segura."
fi

if [ "$ALTAS_NAO_BYPASSED" -gt 0 ]; then
  echo "$ALTAS_NAO_BYPASSED - Alta(s) - A pipeline não pode prosseguir. Precisamos da sua correção dessas vulnerabilidades altas para manter a empresa segura."
fi

CRITICAS_BYPASSED=$((CRITICAS - CRITICAS_NAO_BYPASSED))
if [ "$CRITICAS_BYPASSED" -gt 0 ]; then
  echo "$CRITICAS_BYPASSED - Crítica(s) - Encontra(m)-se na lista de bypass."
fi

if [ "$MEDIAS" -gt 0 ]; then
  echo "$MEDIAS - Média(s) - Vulnerabilidades médias não bloqueiam a pipeline, mas precisamos da sua atenção no relatório."
fi

if [ "$BAIXAS" -gt 0 ]; then
  echo "$BAIXAS - Baixa(s) - Vulnerabilidades baixas não bloqueiam a pipeline, mas é recomendável revisá-las quando possível."
fi

echo ""
echo "Validação do JSON concluída com sucesso."

# Parar a pipeline se houver vulnerabilidades críticas ou altas não bypassed
if [ "$CRITICAS_NAO_BYPASSED" -gt 0 ] || [ "$ALTAS_NAO_BYPASSED" -gt 0 ]; then
  echo "Vulnerabilidades críticas ou altas não bypassed foram encontradas. A pipeline será interrompida."
  exit 1
else
  echo "Nenhuma vulnerabilidade crítica ou alta não bypassed foi encontrada. A pipeline pode continuar."
fi
