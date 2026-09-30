My Pipeline Seguridad automátizado

![SOC L1 - Ivan Ajenjo Morales](./Banner.png) 

![Trivy](https://img.shields.io/badge/TRIVY-HARDENING-C71B26?style=for-the-badge&logo=aqua&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GITHUB%20ACTIONS-SECURITY%20PIPELINE-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Hardening](https://img.shields.io/badge/HARDENING-CI%2FCD-00C853?style=for-the-badge&logo=linux&logoColor=white)
![SOC](https://img.shields.io/badge/SOC-1%20REMEDIATION-FF6F00?style=for-the-badge)

## 🛡️ Procedimiento SOC L1: Remediación Automatizada mediante Pipeline CI/CD

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

## Resumen del laboratorio actual

**Equipo-azul-laboratorio-sociedad-l1-l2:** Laboratorio de parcheo y endurecimiento para **SOC 1 / SOC 2**.

Validación de ciclo de vida de parches en Ubuntu y Windows, deshabilitado de SMBv1 y cierre de puertos (vsftpd/21) con UFW.

**Autor:** Iván Ajenjo Morales | SOC 1 / SOC 2 ITIL SecOps | Licencia MIT

