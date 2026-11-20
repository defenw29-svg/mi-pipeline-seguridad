---

### 4. 🔒 Refuerzo Avanzado de Integridad y Profundidad de Análisis (v3.5)

Para elevar el nivel de garantía en auditorías técnicas y evitar puntos ciegos durante la ejecución automatizada, se incorporan dos controles adicionales de endurecimiento sobre el flujo principal:

#### A. Auditoría Profunda de Historial Git (`fetch-depth: 0`)
* **Riesgo mitigado:** Un escaneo superficial (`--no-git` o clonación *shallow* por defecto) solo inspecciona el último commit, dejando ocultas credenciales o claves API comprometidas en revisiones anteriores del repositorio.
* **Control aplicado:** Se habilita la descarga completa del árbol de commits antes de lanzar Gitleaks, garantizando trazabilidad histórica total (MITRE **T1078**).

```yaml
- name: Checkout completo del repositorio
  uses: actions/checkout@v4
  with:
    fetch-depth: 0

- name: Gitleaks Deep History Scan
  uses: gitleaks/gitleaks-action@v2
  with:
    args: --redact --verbose --report-format=sarif --report-path=gitleaks.sarif
```

#### B. Bloqueo Estricto ante Corrupción de Evidencias (*Hard Fail-Closed*)
* **Riesgo mitigado:** Inyectar un reporte SARIF vacío (`"results": []`) ante un fallo de red permite que el flujo continúe, pero puede interpretarse como un estado limpio si el consumidor posterior no diferencia entre "0 hallazgos" y "fallo de descarga".
* **Control aplicado:** Se sustituye el reporte de respaldo vacío por una abortación explícita (`exit 1`) con limpieza del búfer temporal, asegurando que ninguna caída de red o API degrade silenciosamente la postura de seguridad.

```bash
# Descarga segura de evidencia SARIF con validación estricta
gh api -H "Accept: application/sarif+json" \
  "repos/ github.repository /code-scanning/analyses/ANALYSIS_ID" > codeql-results.tmp

if [ -s "codeql-results.tmp" ] && jq -e '.runs' codeql-results.tmp >/dev/null 2>&1; then
  mv codeql-results.tmp codeql-results.sarif
  echo "✅ Evidencia CodeQL validada e incorporada al SOC Gate."
else
  rm -f codeql-results.tmp
  echo "❌ CRÍTICO: Evidencia SARIF corrupta o inaccesible. Bloqueando despliegue (Fail-Closed)." >&2
  exit 1
fi
```
