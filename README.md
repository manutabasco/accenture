# accenture grupo 5
Marco de control
  NISTAIRMF1.0
  OWASP TOP 10LLM
  2025 OWASP AGENTIC AI
  OWASP API SECURITY TOP 10 2023
  MITREATLAS

  PRESENTACION
https://canva.link/qmtthcj24xgg2ud

propmt importante: 
Rol: Actúa como consultor de ciberseguridad especializado en IA y en el control de agentes.

Contexto: Partimos del marco de control unificado del Excel, que integra NIST AI RMF 1.0, OWASP Top 10 for LLM 2025, OWASP Agentic AI, OWASP API Security 2023 y MITRE ATLAS, y que hemos aplicado al chatbot RAG del cliente.

Tarea: Añade un nivel adicional de detalle que descomponga el marco por cada componente de una arquitectura agéntica:

Entrada (user prompt)
System prompt
Memoria (corto plazo, sesión y largo plazo / vectorial)
RAG e ingesta de documentos
Tools y acciones
MCP (Model Context Protocol)
Guardarraíles de entrada y salida
Conexión con el LLM
Salida y presentación
Orquestador / API
Identidad, observabilidad y cadena de suministro

Para cada componente indica:

Cómo está implementado en el sistema del cliente, con archivo y línea.
La amenaza principal.
Su referencia en cada uno de los 5 marcos.
El control concreto que la mitiga.
Su prioridad (P1–P3).
El caso de prueba que debe ejecutar el agente de testing para verificarlo.

Formato de salida: una hoja nueva en el Excel con un resumen por componente que se recalcule automáticamente al cambiar el estado de cada control.
