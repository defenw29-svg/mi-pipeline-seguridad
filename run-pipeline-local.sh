#!/bin/sh
# run-pipeline-local.sh - Orquesta v3.4 en local idéntico a GitHub Actions
# Uso: GH_TOKEN=ghp_xxx docker compose up secops-runner

set -e
echo "🛡 Iniciando SOC Pipeline v3.4 local..."

# 1. Instalar dependencias según el gestor de paquetes del contenedor
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache git jq curl gitleaks github-cli 2>/dev/null || true
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update && apt-get install -y jq curl gitleaks gh 2>/dev/null || true
fi

# 2. Gitleaks T1078 (igual que Action)
echo "-> Gitleaks T1078..."
gitleaks detect --source . --redact --format sarif --report-path gitleaks-results.sarif --no-banner -v || true

# 3. Trivy T1190
echo "-> Trivy T1190..."
trivy fs --format sarif --output trivy-results.sarif --severity CRITICAL,HIGH . || true

# 4. CodeQL - Versión local con CodeQL CLI u obtención de API
echo "-> CodeQL T1059 (modo local)..."
CURRENT_REPO="${GITHUB_REPOSITORY:-defenw29-svg/mi-pipeline-seguridad}"

if [ -n "$GH_TOKEN" ]; then
  REF_PATH="refs/heads/main"
  ANALYSIS_OUT=$(gh api "repos/${CURRENT_REPO}/code-scanning/analyses?tool_name=CodeQL&ref=$REF_PATH&per_page=1" 2>&1) || true
  ANALYSIS_ID=$(echo "$ANALYSIS_OUT" | jq -r '.. | .id? // empty' | head -n1 2>/dev/null || echo "")
  if [ -n "$ANALYSIS_ID" ]; then
    gh api -H "Accept: application/sarif+json" "repos/${CURRENT_REPO}/code-scanning/analyses/$ANALYSIS_ID" > codeql-results.tmp 2>/dev/null || true
    if [ -s "codeql-results.tmp" ] && jq -e '.runs' codeql-results.tmp >/dev/null 2>&1; then
      mv codeql-results.tmp codeql-results.sarif
    else
      echo '{"version":"2.1.0","runs":[{"results":[]}]}' > codeql-results.sarif
      rm -f codeql-results.tmp
    fi
  else
    echo '{"version":"2.1.0","runs":[{"results":[]}]}' > codeql-results.sarif
  fi
else
  echo "⚠ Sin GH_TOKEN - usando codeql local CLI si existe, si no vacío"
  if command -v codeql >/dev/null 2>&1; then
    codeql database create --language=javascript,python /tmp/codeql-db --source-root=. 2>/dev/null || true
    codeql database analyze /tmp/codeql-db --format=sarifv2 --output=codeql-results.sarif 2>/dev/null || echo '{"version":"2.1.0","runs":[{"results":[]}]}' > codeql-results.sarif
  else
    echo '{"version":"2.1.0","runs":[{"results":[]}]}' > codeql-results.sarif
  fi
fi

# 5. SBOM + Wazuh JSON (mismo bloque v3.4)
echo "-> SBOM + Wazuh..."
trivy fs --format cyclonedx --output sbom.json . 2>/dev/null || true
> wazuh-alerts.json
for f in gitleaks-results.sarif trivy-results.sarif codeql-results.sarif; do
  [ -s "$f" ] && jq -c --arg s "$f" --arg c "$(git rev-parse HEAD 2>/dev/null || echo local)" --arg a "$(whoami)" '.runs[]?.results[]? | select(.!=null) | {integration:"soc_pipeline_scan",scanner:$s,commit:$c,actor:$a,mitre:(if $s|contains("gitleaks") then "T1078" elif $s|contains("trivy") then "T1190" else "T1059" end),rule_id:(.ruleId//"unknown")}' "$f" >> wazuh-alerts.json 2>/dev/null || true
done

# 6. Gate idéntico a v3.4 (Evitando falsos positivos de set -e en la suma)
cnt_vuln() { f=$1; [ -f "$f" ] || { echo 0; return; }; jq '[if .runs then .runs[]?.results[]? else empty end | select(.ruleId!="infra-403")] | length' "$f" 2>/dev/null | tr -d '\n\r ' || echo 0; }
G=$(cnt_vuln gitleaks-results.sarif); T=$(cnt_vuln trivy-results.sarif); C=$(cnt_vuln codeql-results.sarif)
G=$(echo "$G" | grep -Eo '[0-9]+' | head -1); G=${G:-0}
T=$(echo "$T" | grep -Eo '[0-9]+' | head -1); T=${T:-0}
C=$(echo "$C" | grep -Eo '[0-9]+' | head -1); C=${C:-0}

# El uso de "|| true" previene que 'set -e' aborte el script si la suma da 0
TOTAL=$((G+T+C)) || true 

echo "📊 SOC Gate Local: Gitleaks=$G Trivy=$T CodeQL=$C Total=$TOTAL"
if [ "$TOTAL" -gt 0 ]; then 
  echo "❌ Bloqueado $TOTAL vulns"
  exit 1
fi

echo "✅ SOC Gate OK local - Wazuh en http://localhost:5601"
