# SOC-Home-Lab-AWS-Wazuh
Laboratorio de detección de amenazas basado en AWS para demostrar  habilidades de SOC Analyst usando Wazuh SIEM y técnicas MITRE ATT&amp;CK.

## Objetivo
Laboratorio de detección de amenazas basado en AWS para demostrar 
habilidades de SOC Analyst usando Wazuh SIEM y técnicas MITRE ATT&CK.

## Arquitectura
- Wazuh Server: EC2 t3.small, Ubuntu 24.04, us-east-1
- Agente Linux víctima: EC2 t3.micro, Ubuntu 24.04 (Semana 2)
- Agente Windows víctima: EC2 t3.micro, Windows Server (Semana 2)
- Atacante: Kali Linux (local)

## Stack
- SIEM: Wazuh 4.9.2
- Simulación de ataques: Atomic Red Team + Kali Linux
- Framework: MITRE ATT&CK

## Estado del proyecto
- [x] Semana 1 — Infraestructura base y Wazuh desplegado
- [x] Semana 2 — Agentes conectados
- [ ] Semana 3-5 — Detecciones MITRE ATT&CK
- [ ] Semana 6 — Documentación final

## Dashboard
![Wazuh Dashboard](<img width="1919" height="876" alt="image" src="https://github.com/user-attachments/assets/b45d36a0-0be8-4672-a453-2f9623a19e69" />
).
