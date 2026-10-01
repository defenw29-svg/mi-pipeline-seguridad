## 2. Un solo comando (Pipeline v3.4 local)

```bash
chmod +x scripts/run-pipeline-local.sh
docker compose up secops-runner --build
```
- levanta `aquasec/trivy`
- ejecuta `Gitleaks T1078 + Trivy T1190 + CodeQL T1059` con lógica atómica `tmp -> validate -> mv`
- genera `sbom.json + wazuh-alerts.json + *.sarif`
- gate `TOTAL=$((G+T+C))`

## 3. Con Wazuh SIEM completo

```bash
docker compose up -d
docker compose logs -f secops-runner
# http://localhost:5601 -> admin / SecretPassword
```

## Archivo unificado
Usa `docker-compose.unified.yml` como `docker-compose.yml`:
- sin profile = solo pipeline
- con `--profile siem` = pipeline + Wazuh
