# ✅ Estado CISO v1.1 - Detections Validadas
**Repositorio:** mi-pipeline-seguridad | **Autor:** Iván Ajenjo Morales | **Fecha:** 2026-09-30 | **Commits:** 47
**Rol objetivo:** SOC Nivel 1 / Nivel 2 / Nivel 3 ITIL SecOps

## Historial de validación

### ✅ v1.0 - Fundacion - Validado
- Tabla MITRE T1078-T1021 mapeada
- Pila de respuesta Wazuh → Sigma → YARA → UFW
- Refuerzo Gitleaks con SARIF endurecido `--redact --verbose --no-git --report-format=sarif`
- Hipótesis de caza y líneas de persistencia / lateral

### ✅ v1.1 - Detections Sigma - Validado HOY
- `detecciones/T1021_SMB_Lateral.yml` - Movimiento lateral SMB 445 BLOCK - T1021
- `detecciones/T1078_ValidAccounts.yml` - Persistencia SSH cuentas válidas - T1078
- `detecciones/T1070_ClearLogs.yml` - Evasión borrado /var/log - T1070
- Carpeta `/detecciones` creada con 3 reglas experimentales listas para Wazuh

### ⏳ v1.2 - YARA + UFW - Siguiente
- `detecciones/web_backdoor.yar` - Detección webshell PHP
- `scripts/ufw_hardening.sh` - Endurecimiento automatizado

## Evidencias trazables v1.1

- **Control preventivo T1078:** Gitleaks SARIF + Sigma SSH bruteforce > 5 intentos
- **Control detectivo T1190/T1021:** Trivy + CodeQL + Sigma SMB Lateral
- **Control de evasión T1070:** Sigma detecta `rm -rf /var/log` / `shred` / vaciado auth.log

**Laboratorio validado Tier 1 → Tier 2 con detecciones operativas, base lista para Threat Hunting proactivo Tier 3.**
