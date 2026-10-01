<img width="2048" height="1152" alt="image" src="https://github.com/user-attachments/assets/166c31db-b964-42f9-a75a-21a7b6b24d36" />

![SOC L1 - Ivan Ajenjo Morales](./Banner.png) 

![Trivy](https://img.shields.io/badge/TRIVY-HARDENING-C71B26?style=for-the-badge&logo=aqua&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GITHUB%20ACTIONS-SECURITY%20PIPELINE-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Hardening](https://img.shields.io/badge/HARDENING-CI%2FCD-00C853?style=for-the-badge&logo=linux&logoColor=white)
![SOC](https://img.shields.io/badge/SOC-1%20REMEDIATION-FF6F00?style=for-the-badge)

## 🛡️ Procedimiento SOC L1: Remediación Automatizada mediante Pipeline CI/CD

![CI/CD Security Pipeline - SOC Tier 1/2/3](INFOGRAFIA_PIPELINE_SOC.jpg)

Como medida de **endurecimiento y prevención continua (Hardening)** para mitigar vulnerabilidades antes de que lleguen a producción, se ha implementado una canalización automatizada en este repositorio. Este procedimiento intercepta el código en busca de fallos de configuración o dependencias vulnerables antes de su despliegue técnico.

---

### 📑 Ficha del Control de Seguridad (Matriz SecOps)

| Fase del Pipeline | Herramienta | Objetivo Técnico | Tipo de Control |
| :--- | :--- | :--- | :--- |
| **1. Escaneo secreto** | `Gitleaks` | Detectar credenciales, claves API o tokens SSH expuestos en el código fuente. | Preventivo (Bloquea el push) |
| **2. Análisis SAST** | `GitHub CodeQL` | Análisis estático automatizado para identificar malas prácticas y fallos lógicos (Inyecciones, XSS). | Detectivo / Correctivo |
| **3. Escaneo SCA** | `Aqua Trivy` | Escanear el árbol de dependencias (`packages`, librerías de terceros) contra CVEs conocidos. | Preventivo (Filtra severidad Alta/Crítica) |
| **4. Implementación de CD** | `GitHub Actions` | Despliegue técnico seguro y automatizado únicamente si los 3 controles previos arrojan 0 alertas. | Operativo / Automatizado |

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
| **T1070** | Indicator Removal | Defense Evasion | **SARIF + GitHub Security**: preserva evidencia aunque el atacante intente borrar logs |
| **T1021** | Remote Services | Lateral Movement | **UFW + Wazuh**: detecta movimiento lateral vía SSH/RDP/WinRM tras compromiso inicial |

**Stack de respuesta:** `Wazuh SIEM` (recolección) → `Sigma rules` (detección) → `YARA` (clasificación) → `UFW firewall` (contención) → **DETECT · ANALYZE · RESPOND**

🛡️Este pipeline opera en **SOC Tier 1 / Tier 2**, pero deja la base lista para **Threat Hunting proactivo (Tier 3)**.

#### 🔐 Refuerzo Gitleaks - Control Preventivo T1078

**¿Qué hace?** Escaneo profundo de secretos (API keys, tokens, `.env`, claves SSH) en código y en **historial completo de git**, no solo en el último commit.

**Configuración endurecida en este pipeline:**
```yaml
- name: Gitleaks Secret Scan
  uses: gitleaks/gitleaks-action@v2
  with:
    args: --redact --verbose --no-git --report-format=sarif --report-path=gitleaks.sarif
```

**Hipótesis de caza basada en este laboratorio:**
> Asumiendo compromiso previo por servicios endurecidos (vsftpd/21, SMBv1), ¿existe persistencia o movimiento lateral no detectado por controles preventivos?

**Líneas de caza propuestas:**
1.  **Persistencia:** Búsqueda de binarios sospechosos en `/tmp` o `crontab` creados durante el periodo en que `vsftpd/21` estuvo expuesto.

2.  **Movimiento lateral SMB:** Correlación en `auth.log` / `Sysmon Event ID 4624` de intentos de uso de SMBv1 después de su deshabilitación.

3.  **Detección proactiva:** Creación de reglas Sigma/YARA basadas en evidencias SARIF generadas por Trivy y CodeQL para alimentar SIEM (Wazuh / Sentinel) bajo marco MITRE ATT&CK (T1078, T1190).

**Objetivo:** Pasar de remediación reactiva a caza hipotética asumiendo brecha, validando que el endurecimiento con UFW y gestión de ciclo de vida de parches no dejó artefactos residuales.


## 🛡️ Hardening de Arquitectura y Mitigación de Falsos Negativos (SOC Assurance)

El diseño del bloque analítico del pipeline implementa un enfoque defensivo estricto para mitigar ataques de evasión ("Bypass") y garantizar la integridad de las evidencias remitidas a la cola de eventos del SIEM (Wazuh).

### 1. Extracción Resiliente de IDs de Análisis mediante Recursividad (JQ Deep Search)
* **El Problema:** El filtrado rígido basado en arrays estáticos (`.[0].id`) se rompe o cortocircuita de forma silenciosa si la API de GitHub introduce metadatos de paginación adicionales o si los payloads son modificados dinámicamente en entornos federados/Enterprise.
* **La Solución (v3.4):** Se implementa el operador de recursividad profunda de `jq` (`.. | .id? // empty`). Este mecanismo inspecciona transversalmente la estructura del objeto JSON devuelto, garantizando la localización unívoca del identificador del escaneo sin importar el nivel de anidamiento de la respuesta.

### 2. Persistencia Atómica de Evidencias (Write-to-Temp + Validate Pattern)
* **El Problema:** Las redirecciones de flujo directas sobre el archivo definitivo (`gh api ... > codeql-results.sarif`) generan condiciones de carrera si la conexión HTTP se degrada, dejando el archivo truncado, malformado o vacío. Un validador secuencial laxo interpretaría este estado como "0 vulnerabilidades", autorizando despliegues inseguros.
* **La Solución (v3.4):** Se aplica el patrón de escritura atómica utilizado en entornos bancarios de alta criticidad:
  1. Los datos brutos se vuelcan inicialmente en un buffer temporal aislado (`codeql-results.tmp`).
  2. Se valida la existencia y la integridad estructural de la firma del esquema SARIF (`jq -e '.runs'`).
  3. Solo si la estructura lógica es 100% íntegra, se realiza un desplazamiento atómico en el sistema de archivos (`mv`). Si el buffer está corrupto, se genera un reporte estructurado alternativo para alertar al SOC de forma transparente sin enmascarar riesgos.

## Resumen del laboratorio actual

**Equipo-azul-laboratorio-sociedad-l1-l2-l3:** Laboratorio de parcheo y endurecimiento para SOC Tier 1 / Tier 2 / Tier 3.

Validación de ciclo de vida de parches en Ubuntu y Windows, deshabilitado de SMBv1 y cierre de puertos (vsftpd/21) con UFW.

**Autor:** Iván Ajenjo Morales | SOC Tier 1 / Tier 2 / Tier 3 ITIL SecOps | Licencia MIT
