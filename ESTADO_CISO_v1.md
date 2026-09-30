# ✅ Estado CISO v1.0 - Validado
**Repositorio:** mi-pipeline-seguridad | **Autor:** Iván Ajenjo Morales | **Fecha:** 2026-09-30
**Rol objetivo:** SOC Nivel 1 / Nivel 2 / Nivel 3 ITIL SecOps

## Checklist de validación

- ✅ Tabla MITRE T1078-T1021 mapeada
- ✅ Pila de respuesta Wazuh → Sigma → YARA → UFW
- ✅ Refuerzo Gitleaks con SARIF endurecido
- ✅ Hipótesis de caza y líneas de persistencia / lateral

## Evidencias trazables

- **Control preventivo T1078:** Gitleaks con `args: --redact --verbose --no-git --report-format=sarif`
- **Control detectivo T1190:** Trivy + CodeQL SARIF en GitHub Security
- **Control de evasión T1070/T1021:** SARIF preserva evidencia + UFW detecta movimiento lateral SMB/RDP/SSH

## Objetivo Tier 3
> Pasar de remediación reactiva a caza hipotética asumiendo brecha, validando que el endurecimiento con UFW y gestión de ciclo de vida de parches no deja artefactos residuales.

**Laboratorio validado Tier 1 → Tier 2 con base lista para Threat Hunting proactivo Tier 3.**
