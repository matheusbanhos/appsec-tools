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
  local titulo="$1"
  local criticas=$2
  local altas=$3
  local medias=$4
  local baixas=$5

  echo "$titulo:"
  echo "+-------------+-------------+"
  echo "| Severidade  | Quantidade  |"
  echo "+-------------+-------------+"
  printf "| Crítica     | %-11d |\n" $criticas
  printf "| Alta        | %-11d |\n" $altas
  printf "| Média       | %-11d |\n" $medias
  printf "| Baixa       | %-11d |\n" $baixas
  echo "+-------------+-------------+"
}

# Função para imprimir cabeçalho
imprimir_cabecalho() {
  echo "================================================================="
  echo "                ANÁLISE DE SEGURANÇA - RELATÓRIO"
  echo "================================================================="
  echo
}

# Função para imprimir rodapé
imprimir_rodape() {
  echo "================================================================="
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
CRITICAS=$(jq '[.analysisVulnerabilities[].vulnerabilities | select(.severity == "CRITICAL")] | length' "$REPORT_FILE")
ALTAS=$(jq '[.analysisVulnerabilities[].vulnerabilities | select(.severity == "HIGH")] | length' "$REPORT_FILE")
MEDIAS=$(jq '[.analysisVulnerabilities[].vulnerabilities | select(.severity == "MEDIUM")] | length' "$REPORT_FILE")
BAIXAS=$(jq '[.analysisVulnerabilities[].vulnerabilities | select(.severity == "LOW")] | length' "$REPORT_FILE")

# Verificar vulnerabilidades críticas e altas não bypassed
CRITICAS_NAO_BYPASSED=$(jq --argjson bypass_rule "$BYPASS_RULE_ID_JSON" --argjson bypass_vuln "$BYPASS_VULNERABILITY_ID_JSON" '
  [.analysisVulnerabilities[].vulnerabilities | 
   select(.severity == "CRITICAL") | 
   select(
     (.rule_id | . as $item | $bypass_rule | index($item) | not) and
     (.vulnerabilityID | . as $item | $bypass_vuln | index($item) | not)
   )] | 
  length' "$REPORT_FILE")

ALTAS_NAO_BYPASSED=$(jq --argjson bypass_rule "$BYPASS_RULE_ID_JSON" --argjson bypass_vuln "$BYPASS_VULNERABILITY_ID_JSON" '
  [.analysisVulnerabilities[].vulnerabilities | 
   select(.severity == "HIGH") | 
   select(
     (.rule_id | . as $item | $bypass_rule | index($item) | not) and
     (.vulnerabilityID | . as $item | $bypass_vuln | index($item) | not)
   )] | 
  length' "$REPORT_FILE")

CRITICAS_BYPASSED=$((CRITICAS - CRITICAS_NAO_BYPASSED))
ALTAS_BYPASSED=$((ALTAS - ALTAS_NAO_BYPASSED))

# Imprimir relatório
imprimir_cabecalho

imprimir_tabela "VULNERABILIDADES FORA DA ALLOW LIST" $CRITICAS_NAO_BYPASSED $ALTAS_NAO_BYPASSED $MEDIAS $BAIXAS
echo

imprimir_tabela "VULNERABILIDADES NA ALLOW LIST" $CRITICAS_BYPASSED $ALTAS_BYPASSED 0 0
echo

if [ $CRITICAS_NAO_BYPASSED -gt 0 ] || [ $ALTAS_NAO_BYPASSED -gt 0 ]; then
    echo "-----------------------------------------------------------------"
    echo "                    !!! ATENÇÃO !!!"
    echo "      🚫 A PIPELINE NÃO PODE PROSSEGUIR 🚫"
    echo
    echo "Motivo: Foram encontradas vulnerabilidades críticas ou altas fora da Allow List"
    echo "-----------------------------------------------------------------"
    echo
    echo "Análise de Vulnerabilidades:"
    [ $CRITICAS_NAO_BYPASSED -gt 0 ] && echo "► CRÍTICA(s) [$CRITICAS_NAO_BYPASSED] - A pipeline não pode prosseguir."
    [ $ALTAS_NAO_BYPASSED -gt 0 ] && echo "► ALTA(s)    [$ALTAS_NAO_BYPASSED] - A pipeline não pode prosseguir."
    echo "  Necessário correção das vulnerabilidades para manter a segurança do sistema."
else
    echo "-----------------------------------------------------------------"
    echo "                    ✅ VALIDAÇÃO CONCLUÍDA"
    echo "      A PIPELINE PODE CONTINUAR - Vulnerabilidades Permitidas"
    echo "-----------------------------------------------------------------"
    echo
    echo "Análise de Vulnerabilidades:"
    [ $CRITICAS_BYPASSED -gt 0 ] && echo "► CRÍTICA(s) [$CRITICAS_BYPASSED] - Encontra(m)-se na lista de bypass."
    [ $ALTAS_BYPASSED -gt 0 ] && echo "► ALTA(s)    [$ALTAS_BYPASSED] - Encontra(m)-se na lista de bypass."
fi

[ $MEDIAS -gt 0 ] && echo "► MÉDIA(s)   [$MEDIAS] - Vulnerabilidades médias não bloqueiam a pipeline,"
[ $MEDIAS -gt 0 ] && echo "  mas precisam de atenção no relatório."

echo
echo "Validação do JSON concluída com sucesso."
if [ $CRITICAS_NAO_BYPASSED -eq 0 ] && [ $ALTAS_NAO_BYPASSED -eq 0 ]; then
    echo "Nenhuma vulnerabilidade crítica ou alta não bypassed foi encontrada."
fi

imprimir_rodape

# Parar a pipeline se houver vulnerabilidades críticas ou altas não bypassed
if [ $CRITICAS_NAO_BYPASSED -gt 0 ] || [ $ALTAS_NAO_BYPASSED -gt 0 ]; then
    exit 1
else
    exit 0
fi
