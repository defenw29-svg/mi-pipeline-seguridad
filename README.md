<img width="2048" height="1152" alt="image" src="https://github.com/user-attachments/assets/166c31db-b964-42f9-a75a-21a7b6b24d36" />

![SOC L1 - Ivan Ajenjo Morales](./Banner.png)

![Trivy](https://img.shields.io/badge/TRIVY-HARDENING-C71B26?style=for-the-badge&logo=aqua&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GITHUB%20ACTIONS-SECURITY%20PIPELINE-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Hardening](https://img.shields.io/badge/HARDENING-CI%2FCD-00C853?style=for-the-badge&logo=linux&logoColor=white)
![SOC](https://img.shields.io/badge/SOC-1%20REMEDIATION-FF6F00?style=for-the-badge)

## 🛡️ Procedimiento SOC L1: Remediación Automatizada mediante Pipeline CI/CD

![CI/CD Security Pipeline - SOC Tier 1/2/3](pipeline-seguridad.webp)

> **🆕 INFOGRAFÍA NUEVA v3.5 Fail-Closed:** Si SARIF corrupto o vacío -> `exit 1` | NO se inyecta SARIF vacío | deploy BLOQUEADO. Extracción segura de IDs sin Deep Search ambiguo.

Como medida de **endurecimiento y prevención continua (Hardening)** para mitigar vulnerabilidades antes de que lleguen a producción, se ha implementado una canalización automatizada en este repositorio. Este procedimiento intercepta el código en busca de fallos de configuración o dependencias vulnerables antes de su despliegue técnico.

<img width="1920" height="1280" alt="tabla-powerbi-ivan-moderno" src="https://github.com/user-attachments/assets/5c8df628-a8fe-4a52-abe6-4f61a421e541" />
> Dashboard de tu pipeline en estilo Power BI. Los datos salen del pipeline, tú solo los visualizas.

**Datos que genera el pipeline:**
- wazuh-alerts.json - alertas SOC
- codeql-results.sarif - hallazgos SAST
- trivy-report.json - CVEs

**Cómo usarlo en Power BI:**
- Abrir Power BI Desktop - Obtener datos - JSON / CSV
- Importar los 3 archivos y unir por Fecha + Severidad
- Arrastrar: Fecha a Eje X | Herramienta a Leyenda | Hallazgos a Valores
- Publicar en Power BI Service y programar Actualización diaria
- Cuando entra una alerta nueva, el dashboard se actualiza solo

**Cómo usarlo en Tableau:**
- Abrir Tableau - Conectar a datos - JSON / CSV
- Limpiar en Tableau Prep: quitar nulos, cambiar tipos
- Arrastrar: Severidad a Color | Herramienta a Filas | Hallazgos a Columnas
- Publicar en Tableau Cloud y programar Extract Refresh
- Ideal para Data Fundamentals de IBM SkillsBuild, gráficos más bonitos para exponer

**Cuándo usar cada una:**
- Power BI: Para SOC de empresa, informes diarios, la que piden en ofertas
- Tableau: Para el curso, para el portfolio, para impresionar en entrevista
- Las 2 juntas: Power BI para trabajar + Tableau para enseñar

**Truco:**
Si exportas siempre con el mismo formato de CSV, no rehaces el gráfico. Solo sustituyes el archivo y Power BI / Tableau lo refresca solo.

**Archivos en el repo:**
- tabla-powerbi-ivan-moderno.jpg - imagen del dashboard
- tabla-powerbi-ivan-moderno-v2.jpg - versión sin amarillo
---

### 📑 Ficha del Control de Seguridad (Matriz SecOps)

| Fase del Pipeline | Herramienta | Objetivo Técnico | Tipo de Control |
| :--- | :--- | :--- | :--- |
| **1. Escaneo secreto** | `Gitleaks` | Detectar credenciales, claves API o tokens SSH expuestos en el código fuente. | Preventivo (Bloquea el push) |
| **2. Análisis SAST** | `【entity-GitHub¦canonical_name=GitHub】 CodeQL` | Análisis estático automatizado para identificar malas prácticas y fallos lógicos (Inyecciones, XSS). | Detectivo / Correctivo |
| **3. Escaneo SCA** | `Aqua Trivy` | Escanear el árbol de dependencias (`packages`, librerías de terceros) contra CVEs conocidos. | Preventivo (Filtra severidad Alta/Crítica) |
| **4. Implementación de CD** | `【entity-GitHub¦canonical_name=GitHub】 Actions` | Despliegue técnico seguro y automatizado únicamente si los 3 controles previos arrojan 0 alertas. | Operativo / Automatizado |

---

### 📓 Ejemplo de Evidencia Técnica y Remediación

Cuando un analista realiza un cambio en los sistemas o configuraciones y ejecuta un envío (`git push`), el pipeline actúa como un guardián automatizado del SOC:

1. **Detección Precoz:** Si el desarrollador incluye una dependencia vulnerable (ej. una versión antigua sujeta a un CVE crítico), la fase de `Dependency Audit (Trivy)` registrará el fallo.

2. **Generación de Alertas:** El pipeline recopila el informe en formato estándar **SARIF** y lo inyecta automáticamente en la pestaña **Seguridad y calidad -> Code scanning** de GitHub.

3. **Acción del Analista SOC:** El analista recibe la alerta con la línea exacta afectada y la sugerencia de parcheo (ej. *Actualizar paquete a versión X.X*). El despliegue técnico queda congelado hasta que el parche sea aplicado con éxito en el entorno local.

### 🔍 Nota Técnica: Evolución hacia Threat Hunting (SOC Tier 3)

![MITRE Map](INFOGRAFIA_MITRE_TIER3.jpg)

> **Leyenda MITRE ATT&CK - Mapeo del laboratorio:**

| Técnica | Nombre | Fase MITRE | Control en este pipeline |
|---|---|---|---|
| **T1078** | Valid Accounts | Initial Access / Persistence | **Gitleaks**: bloquea `git push` si detecta tokens, API keys o credenciales SSH expuestas |
| **T1190** | Exploit Public-Facing Application | Initial Access | **CodeQL (SAST) + Trivy (SCA)**: detecta inyecciones, XSS y CVEs en librerías de terceros |
| **T1059** | Command and Scripting Interpreter | Execution | **Hipótesis de Hunting (Tier 3)**: búsqueda de `bash`, `python`, `powershell` en `/tmp` / `crontab` |
| **T1070** | Indicator Removal | Defense Evasion | **SARIF + 【entity-GitHub Security¦canonical_name=GitHub】**: preserva evidencia aunque el atacante intente borrar logs |
| **T1021** | Remote Services | Lateral Movement | **UFW + Wazuh**: detecta movimiento lateral vía SSH/RDP/WinRM tras compromiso inicial |

**Stack de respuesta:** `Wazuh SIEM` (recolección) → `Sigma rules` (detección) → `YARA` (clasificación) → `UFW firewall` (contención) → **DETECT · ANALYZE · RESPOND**

🛡️Este pipeline opera en **SOC Tier 1 / Tier 2**, pero deja la base lista para **Threat Hunting proactivo (Tier 3)**.

#### 🔐 Refuerzo Gitleaks - Control Preventivo T1078

**¿Qué hace?** Escaneo profundo de secretos (API keys, tokens, `.env`, claves SSH) en código y en **historial completo de git**, no solo en el último commit.

**Configuración endurecida en este pipeline:**
- name: Gitleaks Secret Scan
  uses: gitleaks/gitleaks-action@v2
  with:
    args: --redact --verbose --no-git --report-format=sarif --report-path=gitleaks.sarif

**Hipótesis de caza basada en este laboratorio:**
> Asumiendo compromiso previo por servicios endurecidos (vsftpd/21, SMBv1), ¿existe persistencia o movimiento lateral no detectado por controles preventivos?

**Líneas de caza propuestas:**
1. **Persistencia:** Búsqueda de binarios sospechosos en `/tmp` o `crontab` creados durante el periodo en que `vsftpd/21` estuvo expuesto.
2. **Movimiento lateral SMB:** Correlación en `auth.log` / `Sysmon Event ID 4624` de intentos de uso de SMBv1 después de su deshabilitación.
3. **Detección proactiva:** Creación de reglas Sigma/YARA basadas en evidencias SARIF generadas por Trivy y CodeQL para alimentar SIEM (Wazuh / Sentinel) bajo marco MITRE ATT&CK (T1078, T1190).

**Objetivo:** Pasar de remediación reactiva a caza hipotética asumiendo brecha, validando que el endurecimiento con UFW y gestión de ciclo de vida de parches no dejó artefactos residuales.

## 🛡️ Hardening de Arquitectura y Mitigación de Falsos Negativos (SOC Assurance) - v3.5

El diseño del bloque analítico implementa un enfoque defensivo estricto para mitigar ataques de evasión ("Bypass") y garantizar la integridad de las evidencias remitidas a Wazuh.

### 1. Extracción Segura de IDs - Sin Deep Search Ambiguo - 🆕 CORREGIDO v3.5

- **Problema:** El filtrado rígido `.[0].id` se rompe silenciosamente si la API de Code Scanning introduce metadatos de paginación `{"total_count": 100, "analyses": [...]}` en 【entity-GitHub¦canonical_name=GitHub】 Enterprise Cloud o si el payload es modificado por un proxy federado. El anterior `.. | .id? | head -n1` también era peligroso, porque cogía el *primer* `.id` de todo el JSON, aunque fuera el del repo o el del actor. **Resultado:** `ANALYSIS_ID` incorrecto -> SARIF incorrecto -> falso 0 fantasma -> bypass del SOC Gate.

ANALYSIS_ID=$(echo "$ANALYSIS_OUT" | jq -r '
  if type == "array" then .[0].id
  elif has("analyses") then .analyses[0].id
  elif has("id") then .id
  else empty end // empty
')

if [ -z "$ANALYSIS_ID" ] || [ "$ANALYSIS_ID" = "null" ]; then
  echo "::error::No se pudo obtener ANALYSIS_ID válido - FAIL CLOSED"
  exit 1
fi

> 💡 **Mecanismo:** Buscamos solo en los lugares donde GitHub documenta el ID del análisis: array directo, `.analyses[0].id` o `.id` raíz. Si no está en ninguno, fallamos en cerrado en vez de inventar un ID.

### 2. Persistencia Atómica de Evidencias (Write-to-Temp + Validate) - 🆕 CORREGIDO v3.5

- **Problema:** La instrucción `gh api ... > codeql-results.sarif` ejecuta una redirección directa en la shell. Si la conexión de red se degrada a mitad de la descarga, deja un archivo truncado e inválido. Un cortocircuito sutil con fallbacks genéricos de tipo `|| echo '{}'` expone al pipeline a una condición de carrera (*race condition*), donde el SOC Gate lee un archivo corrupto antes del formateo, asumiendo un estado limpio erróneo (falso 0).

gh api -H "Accept: application/sarif+json" "repos/${{ github.repository }}/code-scanning/analyses/$ANALYSIS_ID" > codeql-results.tmp

if [ -s "codeql-results.tmp" ] && jq -e '.runs' codeql-results.tmp >/dev/null 2>&1; then
  mv codeql-results.tmp codeql-results.sarif
  echo "✅ CodeQL REAL cargado con éxito."
else
  echo "::error::CodeQL SARIF corrupto o vacío - FAIL CLOSED, deploy bloqueado"
  rm -f codeql-results.tmp
  exit 1
fi

> 🔒 **Garantía DevSecOps:** Patrón de diseño con buffer temporal idéntico al exigido por auditorías **SOC 2 Type II e ISO 27001**. Si el flujo de red se corrompe, el archivo SARIF final jamás se ve alterado a medias, impidiendo por completo que el SOC Gate asuma un estado limpio erróneo.

### 🔒 Refuerzo Avanzado de Integridad y Profundidad de Análisis (v3.5)

Para elevar el nivel de garantía en auditorías técnicas y evitar puntos ciegos durante la ejecución automatizada, se incorporan dos controles adicionales de endurecimiento sobre el flujo principal:

#### A. Auditoría Profunda de Historial Git (fetch-depth: 0)

**Riesgo mitigado:** Un escaneo superficial (`--no-git` o clonación superficial por defecto) solo inspecciona el último commit, dejando credenciales ocultas o claves API comprometidas en revisiones anteriores del repositorio.

**Control aplicado:** Se habilita la descarga completa del árbol de commits antes de lanzar Gitleaks, garantizando trazabilidad histórica total (MITRE T1078).

- name: Checkout completo del repositorio
  uses: actions/checkout@v4
  with:
    fetch-depth: 0

- name: Gitleaks Deep History Scan
  uses: gitleaks/gitleaks-action@v2
  with:
    args: --redact --verbose --report-format=sarif --report-path=gitleaks.sarif

#### B. Bloqueo Estricto ante Corrupción de Evidencias

**Riesgo mitigado:** Inyectar un reporte SARIF vacío (`"results": []`) ante un fallo de red permite que el flujo continúe, pero puede interpretarse como un estado limpio si el consumidor posterior no diferencia entre "0 hallazgos" y "fallo de descarga".

**Control aplicado:** Se reemplaza el informe de respaldo vacío por un aborto específico (`exit 1`) con limpieza del búfer temporal, asegurando que ninguna caída de red o API degrade silenciosamente la postura de seguridad.

gh api -H "Accept: application/sarif+json" "repos/${{ github.repository }}/code-scanning/analyses/$ANALYSIS_ID" > codeql-results.tmp

if [ -s "codeql-results.tmp" ] && jq -e '.runs' codeql-results.tmp >/dev/null 2>&1; then
  mv codeql-results.tmp codeql-results.sarif
  echo "✅ Evidencia CodeQL validada e incorporada al SOC Gate."
else
  rm -f codeql-results.tmp
  echo "❌ CRÍTICO: Evidencia SARIF corrupta o inaccesible. Bloqueando despliegue (Fail-Closed)." >&2
  exit 1
fi

### 💻 Pila tecnológica

**Seguridad y Redes**
![WAZUH](https://img.shields.io/badge/WAZUH-SIEM-005571?style=for-the-badge&logo=wazuh&logoColor=white)
![SIGMA](https://img.shields.io/badge/SIGMA-RULES-00AEEF?style=for-the-badge&logo=sigma&logoColor=white)
![YARA](https://img.shields.io/badge/YARA-MALWARE-FF0000?style=for-the-badge&logo=yara&logoColor=white)
![GITLEAKS](https://img.shields.io/badge/GITLEAKS-T1078-black?style=for-the-badge&logo=git&logoColor=white)
![TRIVY](https://img.shields.io/badge/TRIVY-T1190-1904DA?style=for-the-badge&logo=aqua&logoColor=white)
![CODEQL](https://img.shields.io/badge/CODEQL-T1059-24292E?style=for-the-badge&logo=github&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF3E3E?style=for-the-badge&logo=mitre&logoColor=white)
![PALOALTO](https://img.shields.io/badge/PALOALTO-XSOAR-FF6A00?style=for-the-badge&logo=paloaltonetworks&logoColor=white)
![【entity-CISCO¦canonical_name=CISCO】](https://img.shields.io/badge/CISCO-SECURITY-1BA0D7?style=for-the-badge&logo=cisco&logoColor=white)
![WIRESHARK](https://img.shields.io/badge/WIRESHARK-ANALYSIS-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![UFW](https://img.shields.io/badge/UFW-HARDENING-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)

**Sistemas y Automatización**
![DOCKER](https://img.shields.io/badge/DOCKER-SWARM-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![COMPOSE](https://img.shields.io/badge/COMPOSE-ORQUESTA-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![LINUX](https://img.shields.io/badge/LINUX-UBUNTU-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![BASH](https://img.shields.io/badge/BASH-SCRIPTS-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![POWERSHELL](https://img.shields.io/badge/POWERSHELL-HARDEN-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![WINDOWS](https://img.shields.io/badge/WINDOWS-HARDENING-0078D4?style=for-the-badge&logo=windows11&logoColor=white)
![PYTHON](https://img.shields.io/badge/PYTHON-AUTOMATION-FFC300?style=for-the-badge&logo=python&logoColor=black)
![ACTIONS](https://img.shields.io/badge/GITHUB-ACTIONS-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![SBOM](https://img.shields.io/badge/SBOM-CYCLONEDX-6E40C9?style=for-the-badge&logo=cyclonedx&logoColor=white)

### Resumen del laboratorio actual v3.5 — Blue Team Lead Lab | SOC Tier 3

<img width="2048" height="1152" alt="[STRIPPED 71 bytes]" src="https://github.com/user-attachments/assets/680e2219-1739-4286-aedb-fe630b4d2dab" />

mi-pipeline-seguridad | Equipo-azul-laboratorio-sociedad-l1-l3: Laboratorio de parcheo, endurecimiento y orquestación defensiva + Threat Hunting Proactivo para SOC L1-L3.

Validación de ciclo de vida de parches en Ubuntu/ Windows, deshabilitado SMBv1 y cierre puertos vsftpd/21 con UFW + Pipeline SOC `Gitleaks T1078 + Trivy T1190 + CodeQL T1059` con Gate atómico `tmp -> validate -> mv` y `JQ` seguro sin Deep Search ambiguo. Orquestación local `docker compose up secops-runner` idéntica a Actions -> `wazuh-alerts.json` a Wazuh `http://localhost:5601`.

### 3. 🛡️ Endurecimiento Anti-Bypass y Filosofía Fail-Closed

> **Problema:** Un atacante o un dev puede evadir los controles con `git commit --no-verify`, modificando `.github/workflows/` o provocando un fallo de red para forzar un estado limpio erróneo (falso 0).

#### A. Protección contra Bypass Local (T1078)
- **Problema local:** Husky o cualquier git hook se ejecuta en local, `git commit -n` salta la validación.
- **Solución remota:** **GitHub Push Protection** a nivel de org/repo.
- **Refuerzo (Failsafe):** Gitleaks como `required status check` en Actions.

#### B. Protección del Pipeline (T1553)
- **Pinning por SHA:** Reemplazar `uses: actions/checkout@v4` por hash inmutable.
- **Branch Protection Rule** que exija aprobación obligatoria de CODEOWNERS.
- **Auditoría Estática:** **zizmor** / **actionlint** en PRs para detectar `GITHUB_TOKEN` con permisos excesivos o inyección en `run:`.

#### C. Filosofía Fail-Closed en Red (Anti Falso Limpio)
- **Problema:** Si un comando de red falla en un pipe o Trivy/CodeQL no baja la DB, puede retornar exit `0` con "0 vulnerabilidades".
- **Solución atómica:** Patrón `tmp -> validate -> mv`. Se escribe en temporal, se valida con `jq -e '.runs'` (SARIF) / `'.Results'` (Trivy) y solo si es válido se mueve atómicamente.
- **Refuerzo:** `set -euo pipefail` en todo Bash. Si cae la red, el pipeline falla en cerrado y bloquea el deploy.

**Script de referencia Fail-Closed:**
#!/usr/bin/env bash
set -euo pipefail
TMP=$(mktemp /tmp/trivy-XXXXXX.json)
FINAL="./security/trivy-report.json"
trap 'rm -f "$TMP"' EXIT
trivy image --cache-dir /var/cache/trivy --skip-db-update --format json --output "$TMP" my-app:latest
jq -e '.Results | length > 0' "$TMP" > /dev/null
mkdir -p "$(dirname "$FINAL")"
mv "$TMP" "$FINAL"

#### 📊 Matriz de Trazabilidad de Garantía SOC (CC6.1 / A.8.26)

| Vector de Ataque / Evasión | Control Implementado | Tipo de Control | Evidencia para Auditoría |
| :--- | :--- | :--- | :--- |
| **Bypass Local (`--no-verify`)** | 【entity-GitHub¦canonical_name=GitHub】 Push Protection + Gitleaks como Status Check | Preventivo / Detectivo | Logs de Push denegados + ejecución de Gitleaks en Actions |
| **Modificación de Workflows** | CODEOWNERS + Rule Sets + SHA Pinning | Preventivo | PRs aprobados por SecOps + hashes inmutables en YAML |
| **Falso Limpio por Caída de Red** | Patrón Atómico + `set -euo pipefail` + `jq -e` | Preventivo (Fail-Closed) | Logs CI/CD con Exit > 0 bloqueando deploy |

**Autor:** Iván Ajenjo Morales | SOC Tier 1 / Tier 2 / Tier 3 ITIL SecOps | Licencia MIT
