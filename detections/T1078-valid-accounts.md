# T1078 — Valid Accounts (Persistence / Credential Access)

## Metadata
| Campo | Detalle |
|---|---|
| Técnica MITRE | T1078 - Valid Accounts |
| Sub-técnica | T1136.001 - Local Account |
| Táctica | Persistence, Credential Access, Defense Evasion |
| Fecha | 2026-06-01 |
| Agente objetivo | linux-victim (Ubuntu 24.04) |
| Herramienta de ataque | useradd, usermod (nativos de Linux) |

---

## Objetivo
Simular un atacante creando una cuenta backdoor con privilegios elevados 
en un endpoint Linux post-compromise, y validar que Wazuh detecta tanto 
la creación de la cuenta como su uso posterior.

---

## Entorno
- **Atacante:** Usuario con acceso sudo en linux-victim (simula post-compromise)
- **Víctima:** EC2 t3.micro, Ubuntu 24.04, agente Wazuh 4.14.5
- **SIEM:** Wazuh 4.14.5 en EC2 t3.small, us-east-1

---

## Descripción de la técnica
T1078 consiste en usar credenciales válidas para mantener acceso o 
escalar privilegios. Es especialmente difícil de detectar porque:

- El atacante usa cuentas legítimas del sistema
- No genera tráfico de red anómalo
- Las herramientas de seguridad tradicionales no lo marcan como malicioso
- Puede sobrevivir reinicios, rotación de claves SSH y cambios de contraseña

En entornos reales, esta técnica aparece frecuentemente después de una 
intrusión inicial — el atacante crea una cuenta de servicio con nombre 
genérico para mantener acceso silencioso.

---

## Ejecución del ataque

**Comandos ejecutados en linux-victim:**

```bash
# Paso 1 — Crear cuenta backdoor con nombre genérico
sudo useradd -m -s /bin/bash support_admin

# Paso 2 — Establecer contraseña
sudo passwd support_admin

# Paso 3 — Escalar privilegios agregando al grupo sudo
sudo usermod -aG sudo support_admin

# Paso 4 — Usar la cuenta para simular acceso del atacante
su - support_admin
sudo whoami
```

**Análisis del ataque:**
- `support_admin` — nombre diseñado para parecer cuenta de soporte legítima
- `-s /bin/bash` — shell interactiva, el atacante puede operar normalmente
- `-aG sudo` — privilegios de administrador completos
- El atacante puede ahora hacer SSH directamente con estas credenciales

---

## Evidencia — Logs capturados

### Eventos del sistema (auth.log)
useradd[2341]: new group: name=support_admin, GID=1001
useradd[2341]: new user: name=support_admin, UID=1001, GID=1001,
home=/home/support_admin, shell=/bin/bash

### Alertas generadas en Wazuh

**Creación de la cuenta:**
| Rule ID | Descripción | Level |
|---|---|---|
| 5902 | New user added to the system | 8 |
| 100004 | T1078 - Nueva cuenta creada con privilegios elevados | **14** |

**Uso de la cuenta:**
| Rule ID | Descripción | Level |
|---|---|---|
| 5501 | PAM: Login session opened | 3 |
| 5402 | Successful sudo to ROOT executed | 3 |
| 5555 | PAM: User changed password | 3 |
| 5502 | PAM: Login session closed | 3 |

### Screenshots
![Dashboard alertas T1078](../evidence/T1078/dashboard-overview.png)
![Detalle alerta 100004](../evidence/T1078/alert-100004-detail.png)
![Alertas PAM uso de cuenta](../evidence/T1078/pam-alerts.png)

---

## Análisis de detección

### Detección out-of-the-box — Parcial
Wazuh detectó la creación del usuario con rule 5902 level 8 — aceptable 
pero sin contexto de privilegios. Las alertas de uso de la cuenta 
(PAM, sudo) quedaron en level 3, insuficiente para generar respuesta.

### Problema identificado
Las reglas por defecto no correlacionan:
- Creación de usuario nuevo + agregado a grupo sudo = backdoor probable
- Uso inmediato de sudo por cuenta recién creada = comportamiento anómalo

### Reglas personalizadas escritas

```xml
<rule id="100003" level="12">
  <if_sid>5901</if_sid>
  <description>T1078 - Nueva cuenta de usuario creada en Linux: 
  posible backdoor</description>
  <mitre>
    <id>T1078</id>
    <id>T1136.001</id>
  </mitre>
  <group>attack,persistence</group>
</rule>

<rule id="100004" level="14">
  <if_sid>5901</if_sid>
  <match>sudo|wheel|admin</match>
  <description>T1078 - Nueva cuenta creada con privilegios elevados: 
  alta probabilidad de backdoor</description>
  <mitre>
    <id>T1078</id>
    <id>T1136.001</id>
  </mitre>
  <group>attack,persistence</group>
</rule>
```

**Lógica de las reglas:**
- Rule 100003 — cualquier creación de usuario dispara level 12
- Rule 100004 — si además el usuario tiene privilegios elevados, escala a level 14
- Detección en capas: primero el evento, luego el contexto de riesgo

### Resultado
| Regla | Level | Descripción |
|---|---|---|
| 5902 (default) | 8 | New user added to the system |
| 100003 (custom) | 12 | Nueva cuenta creada en Linux |
| 100004 (custom) | **14** | Nueva cuenta con privilegios elevados |

---

## ¿Qué haría un analista SOC Tier 1?

1. **Identificar la cuenta** — nombre, UID, grupos, shell asignada
2. **Verificar legitimidad** — ¿existe un ticket de IT que justifique esta cuenta?
3. **Revisar historial de uso** — ¿la cuenta ya hizo login? ¿ejecutó sudo?
4. **Buscar el origen** — ¿qué proceso o usuario creó la cuenta?
5. **Contener** — deshabilitar la cuenta inmediatamente si no está justificada
6. **Investigar el vector inicial** — si hay backdoor, hubo compromiso previo
7. **Escalar a Tier 2** — level 14 requiere investigación de incidente completa

---

## Falsos positivos posibles
- Scripts de onboarding que crean cuentas de servicio automáticamente
- Administradores de sistemas creando cuentas durante mantenimiento
- Mitigación: correlacionar con tickets de cambio y ventanas de mantenimiento aprobadas

---

## Comparación con T1053.005
Ambas técnicas buscan persistencia pero con enfoques distintos:

| Aspecto | T1053.005 | T1078 |
|---|---|---|
| Vector | Tarea programada | Cuenta de usuario |
| Visibilidad | Alta — crea archivos | Baja — usa sistema nativo |
| Detección | TaskScheduler logs | auth.log + PAM |
| Dificultad de remoción | Fácil — borrar tarea | Media — requiere auditoría completa |

---

## Mitigaciones recomendadas
- Auditar cuentas de usuario periódicamente con `getent passwd`
- Alertar sobre cualquier usuario agregado al grupo sudo fuera de ventanas de mantenimiento
- Implementar PAM con logging estricto
- Usar `last` y `lastlog` regularmente para detectar cuentas inactivas con acceso reciente
- Configurar File Integrity Monitoring sobre `/etc/passwd` y `/etc/shadow`

---

## Referencias
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1136.001](https://attack.mitre.org/techniques/T1136/001/)
- [Wazuh PAM Rules](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Linux useradd man page](https://linux.die.net/man/8/useradd)

