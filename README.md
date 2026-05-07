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
- [ ] Semana 2 — Agentes conectados
- [ ] Semana 3-5 — Detecciones MITRE ATT&CK
- [ ] Semana 6 — Documentación final

## Dashboard
![Wazuh Dashboard_MainPage](<img width="1917" height="873" alt="Wazuh-mainpage" src="https://github.com/user-attachments/assets/dee0351d-9ca8-450b-8df8-a489753d4826" />
)
