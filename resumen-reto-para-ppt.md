# Reto Zero Day Talent: framework de securización de agentes de IA
**Resumen de todo el trabajo para montar la presentación**
Caso: chatbot RAG del cliente → https://github.com/Zlash65/rag-bot-fastapi (commit `2308bb8`, 26 ficheros analizados)

---

## 1. El reto
Elaborar un **framework de securización de IA** (amenazas, controles y gobierno) y **generar agentes que puedan probarlo**, aplicado al agente del cliente.

**Marcos de control utilizados (5):**
| Marco | Para qué lo usamos |
|---|---|
| **NIST AI RMF 1.0** | Paraguas de gobierno y gestión de riesgos: GOVERN, MAP, MEASURE, MANAGE |
| **OWASP Top 10 for LLM Applications 2025** | Riesgos del modelo, el prompt y el RAG (LLM01–LLM10) |
| **OWASP Agentic AI** (Top 10 ASI01–ASI10 + Threats & Mitigations T1–T15) | Riesgos de memoria, herramientas y autonomía |
| **OWASP API Security Top 10 2023** | Riesgos de la API FastAPI que expone el agente |
| **MITRE ATLAS** | Técnicas reales del atacante para escenarios y pruebas |

---

## 2. El sistema del cliente (qué es antes de evaluarlo)
**Arquitectura:** Streamlit (cliente) → FastAPI (7 endpoints) → LangChain → ChromaDB → LLM externo (Groq Llama 3 / Google Gemini).
**Flujo:** el usuario sube PDFs → se trocean (500 tokens) → se crean embeddings → se guardan en Chroma → en cada pregunta se recuperan 3 trozos → se envían al LLM con la pregunta → la respuesta se pinta en pantalla.

**Tipos de memoria**
| Memoria | Dónde | Detalle |
|---|---|---|
| Conversación en el LLM | — | **No hay**: cada pregunta va aislada |
| Historial de chat | Navegador (`st.session_state`) | Se puede descargar en CSV |
| **Memoria de conocimiento (RAG)** | Chroma en disco | **Persistente, acumulativa y compartida por TODOS los usuarios**; "Reset" no la borra |
| PDFs originales | `./temp/` | Nunca se borran |

**Guardarraíles actuales:** solo un system prompt mínimo, una lista blanca de modelos (solo en `/chat`) y la comprobación de la extensión `.pdf` con tamaño ≤ 200 MB.
**No tiene:** autenticación, aislamiento entre usuarios, filtros de entrada o salida, rate limit, cuotas, auditoría ni TLS.
**Herramientas / MCP:** ninguno, solo lee y responde (nivel de autonomía **L1**).
**Terceros:** Groq y Google reciben las preguntas y trozos de los documentos. Con Gemini, **los documentos enteros salen a Google** para calcular los embeddings.

---

## 3. Hallazgos técnicos (evidencias en el código)
| ID | Hallazgo | Dónde | Severidad |
|---|---|---|---|
| H1 | Ningún endpoint tiene autenticación ni autorización | `server/api/routes.py` | **Crítica** |
| H2 | Path traversal: usa el nombre de fichero del cliente para guardar | `document_processor.py:34` | **Crítica** |
| H3 | Memoria vectorial compartida por todos los usuarios | `config/settings.py:24` | Alta |
| H4 | Contexto RAG sin delimitar y system prompt débil → inyección indirecta | `llm_chain_factory.py:16` | Alta |
| H5 | La respuesta se pinta como Markdown → exfiltración con imágenes | `client/components/chat.py:30,50` | Alta |
| H6 | Sin límites: 200 MB, sin rate limit, sin max_tokens | `document_processor.py:14` | Alta |
| H7 | `/vector_store/search` devuelve trozos de documentos a cualquiera | `routes.py` | Alta |
| H8 | Errores internos devueltos al cliente | `routes.py:60,71,82,111` | Media |
| H9 | Proveedor no validado en varios endpoints | `routes.py` | Media |
| H10 | Logs en DEBUG sin saber quién hace qué | `utils/logger.py:6,13` | Media |
| H11 | Dependencias sin versión fijada | `requirements.txt` | Media |
| H12 | Modo desarrollo: `reload=True`, `/docs` público, HTTP sin TLS | `main.py:21` | Media |
| H13 | PDFs temporales nunca borrados | `document_processor.py` | Media |
| H14 | Datos a terceros (Groq/Google) sin contrato | `vector_database.py` | Alta |

---

## 4. Registro de riesgos
Puntuación: **Probabilidad (1–5) × Impacto (1–5) × Factor de autonomía** (L1 = 1,2)
| ID | Riesgo | P×I | Con autonomía | Nivel |
|---|---|---|---|---|
| R1 | Acceso sin autenticar | 25 | 30 | **Crítico** |
| R2 | Fuga de documentos entre usuarios (memoria compartida) | 20 | 24 | **Crítico** |
| R3 | PDF envenenado / inyección indirecta | 16 | 19,2 | **Crítico** |
| R4 | Exfiltración por la salida (Markdown) | 12 | 14,4 | Alto |
| R5 | Path traversal | 12 | 14,4 | Alto |
| R6 | Consumo descontrolado (coste / DoS) | 12 | 14,4 | Alto |
| R7 | Datos confidenciales a terceros | 12 | 14,4 | Alto |
| R8 | Respuestas sin fuente | 9 | 10,8 | Medio |
| R9 | Sin trazabilidad | 8 | 9,6 | Medio |
| R10 | Vulnerabilidades en dependencias | 9 | 10,8 | Medio |

> Si el cliente añadiera una herramienta como `send_email` (autonomía L3, factor 1,7), **R3 pasaría de 19,2 a 27,2**: el mismo PDF envenenado podría enviar correos.
> Los factores de autonomía y los umbrales son **criterio propio del equipo**, no vienen de ningún marco oficial.

---

## 5. Marco de gobierno y gestión de riesgos: NIST AI RMF 1.0
31 controles en las 4 funciones:

| Función | Controles clave |
|---|---|
| **GOVERN** (gobierno) | Política de uso de IA · RACI con propietario del riesgo · tolerancia al riesgo · inventario de sistemas de IA · contratos con Groq y Google (no entrenamiento, región UE) · plan de contingencia del proveedor · supervisión humana · formación · canal de incidencias · revisión trimestral |
| **MAP** (contexto) | Ficha del sistema y aviso de IA · clasificación de datos · evaluación de impacto RGPD y AI Act · SBOM · modelado de amenazas |
| **MEASURE** (medición) | Red teaming antes de cada despliegue (**KPI ≥ 95 % de inyecciones bloqueadas, ≤ 5 % falsos positivos**) · prueba de aislamiento (**0 fugas entre usuarios**) · PII · citas · monitorización · trazabilidad |
| **MANAGE** (gestión) | **Decisión go/no-go** · plan de tratamiento · riesgo residual firmado · **botón de apagado (< 5 min)** · playbook de incidentes (purgar el PDF envenenado) · seguimiento de terceros · retención y borrado |

**Decisión de gobierno: NO-GO a producción** hasta mitigar R1, R2 y R3.

---

## 6. Catálogo unificado de controles (un control → varios marcos)
49 controles, cada uno mapeado a los 5 marcos a la vez. Ejemplos para la diapositiva:

| Control | NIST AI RMF | OWASP LLM | OWASP Agentic | OWASP API | MITRE ATLAS |
|---|---|---|---|---|---|
| **AC-01** Autenticación OAuth2/JWT | MEASURE 2.7 | LLM06 | ASI03 | API2 | AML.T0040 |
| **AC-03** Memoria aislada por usuario | MEASURE 2.10 | LLM08, LLM02 | ASI06 | API1 | AML.T0070, T0057 |
| **LL-01** Contexto delimitado como "no fiable" | MEASURE 2.7 | LLM01, LLM07 | ASI01 | — | AML.T0051.001 |
| **IN-04** Escanear PDFs antes de indexar | MEASURE 2.7 | LLM01, LLM04 | ASI06 | — | AML.T0070 |
| **LL-04** Respuesta sin imágenes remotas | MEASURE 2.6 | LLM05 | ASI09 | — | AML.T0077 |
| **PL-01** Rate limiting | MEASURE 2.4 | LLM10 | ASI08 | API4 | AML.T0029 |

---

## 7. Detalle por componente de la arquitectura agéntica
52 controles organizados por componente, cada uno con su caso de prueba:

| Componente | Nº controles | P1 | Estado hoy |
|---|---|---|---|
| 1. Entrada (user prompt) | 4 | 3 | Sin controles |
| 2. System prompt | 4 | 2 | Mínimo |
| 3. Memoria | 6 | 1 | Compartida, sin aislamiento |
| 4. RAG / ingesta | 6 | 2 | Sin escaneo, path traversal |
| 5. Tools / acciones | 4 | 1 | No hay (controles de diseño) |
| 6. MCP | 4 | 0 | No hay (controles de diseño) |
| 7. Guardrails | 5 | 3 | No existen |
| 8. Conexión con el LLM | 6 | 3 | Sin límites ni contratos |
| 9. Salida | 2 | 2 | Markdown sin sanear |
| 10. Orquestador / API | 5 | 5 | **El más débil** |
| 11. Comunicación entre componentes | 1 | 1 | HTTP sin TLS |
| 12. Observabilidad | 3 | 2 | Sin auditoría |
| 13. Cadena de suministro | 2 | 0 | Sin versiones fijadas |
| **Total** | **52** | **25** | **0 % implementado** |

---

## 8. Metodología unificada (MUEA): del agente del cliente a sus riesgos
Sirve para **cualquier cliente**, no solo para este:

1. **Perfilar el agente:** 10 preguntas (¿RAG? ¿memoria compartida? ¿tools? ¿MCP? ¿multiagente? ¿API pública? ¿terceros? ¿datos personales?). Cada "sí" activa sus riesgos en los 5 marcos. Se asigna un **nivel de autonomía de L0 a L4**.
2. **Descomponer la arquitectura** en 8 capas (entrada, ingesta, orquestador, memoria, prompt + LLM, tools/MCP, guardarraíles, salida) y 4 transversales (identidad, observabilidad, cadena de suministro, gobierno), marcando los **límites de confianza**.
3. **Matriz unificada:** capa → riesgo → los 5 marcos → control → prueba.
4. **Puntuar:** P × I × autonomía.
5. **Probar con agentes** (ver punto 9).
6. **Decidir go/no-go** según NIST MANAGE 1.1, con hoja de ruta.

**Regla de oro:** todo dato que entra cruzando un límite de confianza (usuario → backend, tercero → backend) es no fiable y necesita un control en ese punto.

---

## 9. Agentes que prueban el framework
| Agente | Qué prueba | Marco principal | Estado |
|---|---|---|---|
| **A1 Auditor de gobierno** (`nist_rmf_agent.py`) | Revisa el repo contra 21 controles, puntúa por función y da go/no-go | NIST AI RMF | **Hecho y probado** |
| A2 Red team de prompts | Inyecciones, jailbreaks y extracción del system prompt (garak / promptfoo) | OWASP LLM + ATLAS | Diseñado |
| A3 Envenenador de RAG | Sube PDFs con instrucciones ocultas | OWASP Agentic ASI06 | Diseñado |
| A4 Auditor de API | Sin token, otro usuario, payloads gigantes, ráfagas | OWASP API 2023 | Diseñado |
| A5 Aislamiento de memoria | El usuario B intenta leer el documento del usuario A | LLM08 + API1 | Diseñado |
| A6 Auditor de salida | Fuerza imágenes, enlaces y PII en la respuesta | LLM05 + ATLAS | Diseñado |
| A7 Auditor de agencia | Herramientas no permitidas, escalada (si hubiera tools) | ASI02/03/05 | Diseñado |

**Resultado del agente A1 sobre el repo:** GOVERN 0 %, MAP 0 %, MEASURE 0 %, MANAGE 0 % → **NO-GO**.
**Demo antes/después:** con política, RACI, ficha del modelo, nombre de fichero uuid y contexto delimitado, GOVERN sube al 100 %. Sigue en **NO-GO** porque faltan la autenticación, el aislamiento y el red teaming. **El agente no se deja engañar por "solo papeles".**
- Devuelve código de salida 1 si da NO-GO, así que sirve como **puerta en CI/CD**.
- Opción `--llm`: resumen ejecutivo con IA. Guardarraíl: al LLM solo le pasa los resultados, nunca el código, y no puede cambiar el veredicto.

---

## 10. Hoja de ruta para llegar a GO
| Fase | Qué |
|---|---|
| **Semana 1 (P1)** | Autenticación y roles · memoria aislada por usuario · subida segura (uuid, magic bytes, límites) · prompt reforzado · filtros de entrada y salida · rate limit · errores genéricos · auditoría · botón de apagado |
| **Semanas 2–4 (P2)** | Escaneo de PDFs · procedencia y purga de la memoria · contratos con terceros · cuotas de tokens · citas · SIEM · dependencias fijadas |
| **Antes de añadir tools o MCP** | Allowlist, JSON Schema, aprobación humana, credenciales efímeras, servidores MCP firmados |

---

## 11. Propuesta de diapositivas (unas 10)
| # | Diapositiva | Contenido | Material |
|---|---|---|---|
| 1 | Portada | Framework de securización de agentes de IA | — |
| 2 | El reto y el enfoque | 5 marcos, cada uno con su papel (tabla del punto 1) | — |
| 3 | El sistema del cliente | Arquitectura + memoria + guardarraíles actuales | `arquitectura.jpg` |
| 4 | Mapa de riesgos | Diagrama con zonas de confianza y riesgos por flujo | `diagrama-riesgos-arquitectura.png` |
| 5 | Top hallazgos | Los 3 críticos + los 4 altos con archivo y línea | Punto 3 |
| 6 | Gobierno NIST AI RMF | Las 4 funciones, KPIs, decisión NO-GO | Punto 5 |
| 7 | Un control, cinco marcos | Tabla de trazabilidad | Punto 6 |
| 8 | Metodología MUEA | Los 6 pasos y el factor de autonomía | Punto 8 |
| 9 | Agentes de prueba + **demo** | Ejecutar `nist_rmf_agent.py` → NO-GO, antes y después | Punto 9 |
| 10 | Hoja de ruta y conclusión | Semana 1 / 2–4 / antes de tools | Punto 10 |

**Mensajes clave para decir en voz alta:**
- "OWASP nos dice **qué** puede romperse; NIST AI RMF nos dice **quién responde, cómo lo medimos y qué hacemos**."
- "Un mismo control cubre varios marcos: la autenticación cierra API2, ASI03 y MEASURE 2.7 a la vez."
- "El riesgo crece con la autonomía: el mismo PDF envenenado que hoy solo engaña, mañana con una tool podría actuar."
- "El gobierno no se queda en un documento: un agente lo comprueba en cada despliegue y bloquea la salida a producción."

---

## 12. Ficheros entregados
| Fichero | Qué es |
|---|---|
| `marco-seguridad-ia-ragbot.xlsx` | **Excel maestro**: hallazgos, riesgos, 49 controles unificados, hoja por cada marco, 52 controles por componente, resúmenes con go/no-go automático |
| `grupo-A-nist-ai-rmf.md` | Marco de gobierno y gestión de riesgos NIST AI RMF 1.0 |
| `marco-control-ragbot.md` | Primer marco de control técnico |
| `metodologia-unificada-agentes.md` | Metodología MUEA completa |
| `diagrama-riesgos-arquitectura.png` / `.svg` | Diagrama de riesgos sobre la arquitectura |
| `nist_rmf_agent.py` | Agente auditor (Python sin dependencias): `python nist_rmf_agent.py ./rag-bot-fastapi --md informe.md` |
| `informe-nist-rmf.md` / `informe-despues.md` | Resultado del agente antes y después |

## 13. Avisos antes de presentar
- Comprobar en atlas.mitre.org los IDs de **MITRE ATLAS**, sobre todo AML.T0077, AML.T0024 y AML.T0048.
- Comprobar los códigos de las **subcategorías de NIST AI RMF** con el documento oficial (NIST AI 100-1).
- Los **factores de autonomía y los umbrales** son criterio propio del equipo.
- Las opciones `--url` y `--llm` del agente no se han probado (no había API arrancada ni clave de LLM).
- Desde agosto de 2026 existe una edición **2026 del OWASP LLM Top 10** con otra numeración (p. ej. Excessive Agency pasa a LLM03). Usamos la de 2025, como pedía el reto.
