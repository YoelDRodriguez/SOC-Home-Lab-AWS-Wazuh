Detections/T1110-brute-force.md
# T1110 — Brute Force (SSH)

## Metadata
| Campo | Detalle |
|---|---|
| Técnica MITRE | T1110 - Brute Force |
| Sub-técnica | T1110.001 - Password Guessing |
| Táctica | Credential Access |
| Fecha | 2026-05-12 |
| Agente objetivo | linux-victim (Ubuntu 24.04) |
| Herramienta de ataque | Hydra v9.6 |

---

## Objetivo
Simular un ataque de fuerza bruta contra el servicio SSH de un endpoint 
Linux y validar que Wazuh detecta y alerta correctamente los intentos 
de autenticación fallida.

---

## Entorno
- **Atacante:** Kali Linux 2025.4 (VirtualBox local)
- **Víctima:** EC2 t3.micro, Ubuntu 24.04, agente Wazuh 4.14.5
- **SIEM:** Wazuh 4.14.5 en EC2 t3.small, us-east-1

---

## Descripción de la técnica
T1110 consiste en intentar acceder a cuentas mediante prueba sistemática 
de contraseñas. Es una de las técnicas más comunes en ataques reales, 
especialmente contra servicios expuestos a internet como SSH.

En entornos corporativos, SSH expuesto sin controles adicionales 
(fail2ban, MFA, allowlist de IPs) es un vector de entrada frecuente.

---

## Configuración previa
Para que el ataque fuera posible, se habilitó autenticación por contraseña 
en el endpoint víctima — deshabilitada por defecto en AWS EC2:

```bash
# /etc/ssh/sshd_config
PasswordAuthentication yes
KbdInteractiveAuthentication yes
```

> **Nota:** Esta configuración es intencional para el lab. En producción, 
> la autenticación por contraseña debe estar deshabilitada.

---

## Ejecución del ataque

**Herramienta:** Hydra  
**Comando ejecutado desde Kali:**

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://<IP-VICTIM> -t 4 -V
```

**Wordlist:** rockyou.txt (14,344,399 contraseñas)  
**Threads:** 4  
**Usuario objetivo:** root

---

## Evidencia — Alertas generadas en Wazuh

**Total de alertas generadas:** 683

| Rule ID | Descripción | Level | Cantidad |
|---|---|---|---|
| 5785 | Maximum authentication attempts exceeded | 8 | Alta |
| 5720 | sshd: Multiple authentication failures (Brute Force) | 10 | Alta |
| 5551 | PAM: Multiple failed logins in small period of time. | 10 | Alta |


### Screenshots
![Dashboard general](../Evidence/T1110/ <img width="1917" height="876" alt="Main Dashboard- linux-victim" src="https://github.com/user-attachments/assets/9c1021ec-4dca-4d2e-ad6e-001e8f314871" />
)
![Detalle alerta 5720](../Evidence/T1110/ <img width="1918" height="872" alt="sshd-Multiple authentication failures_ID5720" src="https://github.com/user-attachments/assets/d3b24be6-610c-499a-8881-66f19dbdaf46" />
)
![Timeline de alertas](../Evidence/T1110/ <img width="1918" height="872" alt="TimeLine_Dashboard" src="https://github.com/user-attachments/assets/23a3ff48-b4d8-4ff3-aa0f-a260126783aa" />
)

---

## Análisis

### ¿Qué detectó Wazuh?
Wazuh correlacionó múltiples intentos de autenticación fallida desde 
la misma IP origen y escaló la alerta al **level 10** (rule 5720), 
indicando un patrón de brute force activo — no solo fallos aislados.

### ¿Qué haría un analista SOC Tier 1?
1. **Identificar la IP origen** del ataque y verificar si es conocida
2. **Confirmar que no hubo autenticación exitosa** después de los intentos
3. **Escalar** si el volumen es alto o si hay éxito posterior
4. **Recomendar bloqueo** de la IP en el Security Group de AWS
5. **Documentar** el incidente con timeline y evidencia

### Falsos positivos posibles
- Usuarios legítimos que olvidaron su contraseña pueden generar 
  rule 5716 en bajo volumen
- La diferencia clave es el volumen y la velocidad — rule 5720 
  solo dispara ante múltiples fallos consecutivos desde la misma IP

---

## Detección — Reglas de Wazuh

Wazuh detectó esta técnica con reglas **out-of-the-box** sin necesidad 
de reglas personalizadas. Las reglas clave:

**Rule 5720 — Brute force detection:**
```xml
<rule id="5720" level="10" frequency="6" timeframe="120">
  <if_matched_sid>5716</if_matched_sid>
  <description>sshd: Multiple authentication failures.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

Esta regla dispara cuando hay 6 o más fallos (rule 5716) 
en una ventana de 120 segundos desde la misma IP.

---

## Mitigaciones recomendadas
- Deshabilitar autenticación por contraseña en SSH (`PasswordAuthentication no`)
- Implementar fail2ban para bloqueo automático de IPs
- Restringir acceso SSH a IPs conocidas via Security Groups
- Usar MFA para acceso SSH en entornos productivos
- Monitorear rule 5720 como indicador de compromiso activo

---

## Referencias
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [Wazuh Rule 5720](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Hydra - THC](https://github.com/vanhauser-thc/thc-hydra)
