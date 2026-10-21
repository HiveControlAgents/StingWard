<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/banner-es-dark.png">
    <img alt="Stingward: revisión de seguridad para apps hechas con IA, skills de Claude Code y servidores MCP" src="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/banner-es-light.png" width="820">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/HiveControlAgents/StingWard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/HiveControlAgents/StingWard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/stingward/"><img alt="PyPI" src="https://img.shields.io/pypi/v/stingward?color=f5b83d&label=pypi"></a>
  <a href="https://www.npmjs.com/package/stingward"><img alt="npm" src="https://img.shields.io/npm/v/stingward?color=f5b83d"></a>
  <a href="https://pypi.org/project/stingward/"><img alt="Python 3.9+" src="https://img.shields.io/pypi/pyversions/stingward"></a>
  <img alt="Cero dependencias" src="https://img.shields.io/badge/dependencias-0-brightgreen">
  <a href="https://github.com/HiveControlAgents/StingWard/blob/main/LICENSE"><img alt="Licencia Apache 2.0" src="https://img.shields.io/badge/licencia-Apache%202.0-blue"></a>
  <a href="#calidad"><img alt="stingward: A" src="https://img.shields.io/badge/stingward-A-brightgreen"></a>
</p>

<p align="center">
  <a href="https://github.com/HiveControlAgents/StingWard/blob/main/README.md">English</a> · <a href="https://github.com/HiveControlAgents/StingWard/blob/main/README.pt-BR.md">Português</a> · <b>Español</b>
</p>

Cada vez más gente publica apps, skills de Claude Code y servidores MCP escritos con IA. Pocos saben qué es una CVE, por qué `NEXT_PUBLIC_OPENAI_API_KEY` es un problema, o que una skill puede esconder instrucciones que solo el modelo lee. **Stingward encuentra esos agujeros y explica, con palabras simples, cómo cerrar cada uno.**

> Los informes salen en inglés (`--lang en`) o portugués (`--lang pt`). Esta página está en español; la herramienta todavía no.

<p align="center">
  <img alt="stingward skill ./pdf-helper: Do not install yet. Instrucción oculta en Unicode, un script que lee las credenciales de AWS y las envía a webhook.site, shell sin restricciones. Nota F." src="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/demo-skill-en.gif" width="820">
</p>

<p align="center"><sub>Una skill que parece un asistente de PDF. Stingward decodifica la instrucción invisible y encuentra el robo de claves antes de que la instales.</sub></p>

## Inicio rápido

| Dónde | Cómo |
|---|---|
| **Claude Code** | `/plugin marketplace add HiveControlAgents/StingWard` y luego `/plugin install stingward@stingward`. Después pregunta *"is my project secure?"* o *"can I install github.com/x/y?"* |
| **Terminal** | `pipx install stingward` (o `uvx stingward`, o `npx stingward` con Python 3.9+ instalado) y ejecuta `stingward` en tu proyecto |
| **GitHub** | Agrega la [Action](#github-action): comenta en cada PR, llena la pestaña Security y vuelve a revisar todos los días |

```bash
stingward                         # audita el proyecto de la carpeta actual
stingward skill ./alguna-skill    # audita una skill, plugin o servidor MCP antes de instalarlo
stingward skill dueno/repo        # ...directo desde GitHub (también acepta URLs .../tree/rama/subcarpeta)
stingward agents                  # audita la configuración de Claude Code, Claude Desktop, Cursor, Codex y Gemini de esta máquina
```

Sin cuenta, sin telemetría, sin dependencias: Python 3.9+ puro, en Linux, macOS y Windows.

## Qué encuentra

| Área | Ejemplos |
|---|---|
| **Dependencias** | CVEs conocidas y **paquetes maliciosos** en lockfiles de npm, Yarn, pnpm, Bun, pip, Poetry, uv, Pipenv, PDM, Go, Cargo, Bundler, Composer y NuGet. Priorizados por **CISA KEV** (explotadas ahora mismo) y **EPSS** (probabilidad de explotación), con la única actualización que corrige todo lo conocido. Sin lockfile, también revisa la versión más baja que acepta cada rango (`Pillow>=10`, `^1.6.0`). |
| **Secretos** | Claves de API (OpenAI, Anthropic, GitHub, AWS, Google, Stripe, Slack...), claves privadas, `service_role` de Supabase, webhooks, contraseñas en URLs, `.env` en git o fuera del `.gitignore`. El valor nunca se imprime. |
| **Apps hechas con IA** | Secretos detrás de `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_`, `dangerouslyAllowBrowser`, CORS abierto, tablas de Supabase sin RLS o con `using (true)`, reglas de Firebase abiertas, modo debug, JWT sin verificar la firma. En código que llama a un modelo: su respuesta llegando a `eval`, un shell, SQL o HTML, datos de la petición dentro del prompt de sistema, rutas de IA sin login y sin límite de uso, `trust_remote_code` y `torch.load` inseguro, agentes con una herramienta de Python REPL o shell. En servidores MCP y herramientas de agentes: argumentos que escribe el modelo llegando a un shell, `eval`, SQL, una ruta de archivo o una URL que el servidor descarga. |
| **Código** | Inyección de SQL, de comandos y de código, `pickle` y YAML inseguro, XSS (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`), verificación de TLS desactivada, path traversal, SSRF, redirecciones abiertas, `Math.random` para tokens y hashes rápidos para contraseñas. Python se lee con `ast` y JavaScript/TypeScript con patrones ajustados que siguen los datos de la petición dentro de cada función. |
| **Agentes y MCP** | `bypassPermissions`, `Bash(*)`, hooks con `curl \| sh`, `enableAllProjectMcpServers`, servidores MCP sin versión fija, tokens en `.mcp.json`, MCP remoto sin HTTPS, paquetes MCP vulnerables como `mcp-remote` (CVE-2025-6514). |
| **Skills y prompts** | Unicode invisible (caracteres de etiqueta, Trojan Source, ancho cero), "ignora las instrucciones anteriores", "no le digas al usuario", lectura de `~/.ssh` o `~/.aws` con llamada a internet, `curl \| bash`, reverse shells, código ofuscado, servicios de captura (webhook.site, ngrok...), scripts de instalación, `allowed-tools: Bash`, instrucciones ocultas en la descripción de herramientas MCP. |

Las 50 reglas, con severidad, ejemplos y corrección (en inglés): [docs/rules.md](https://github.com/HiveControlAgents/StingWard/blob/main/docs/rules.md).

<p align="center">
  <img alt="stingward ./my-saas: clave de OpenAI expuesta con NEXT_PUBLIC_, la respuesta del modelo ejecutada como comando de shell, next 14.1.0 con CVE-2025-29927 (EPSS de 99%), SQL y una ruta de archivo armados con datos de la petición, un servidor que descarga cualquier URL, tabla de Supabase sin RLS, requests cuya versión mínima permitida tiene fallas conocidas. Nota F." src="https://raw.githubusercontent.com/HiveControlAgents/StingWard/main/docs/assets/demo-app-en.gif" width="820">
</p>

<p align="center"><sub>Una app típica hecha con IA, con Next.js y Supabase. Prueba las dos demos en un clon de este repositorio: <code>python scripts/demo/fixtures.py demo</code>, luego <code>stingward skill demo/pdf-helper</code> y <code>stingward demo/my-saas</code>.</sub></p>

## Cómo funciona

1. **Lista tus archivos**, saltando carpetas de dependencias y de build como `node_modules` y `dist`. Al auditar una skill de terceros sí lee el build, porque es lo que realmente se ejecuta.
2. **Lee los lockfiles** y consulta a [OSV.dev](https://osv.dev) por todos los paquetes y versiones en una sola llamada. Las CVEs de [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) pasan a críticas; [EPSS](https://www.first.org/epss/) y [NVD](https://nvd.nist.gov) completan la probabilidad y las notas que faltan.
3. **Ejecuta las revisiones** de secretos, errores de apps, configuración de agentes y contenido de skills, según el contexto: carpetas de pruebas, documentación y ejemplos pesan menos, y en una skill de terceros un texto tranquilizador puede bajar un hallazgo a medio, pero nunca esconderlo.
4. **Escribe el informe**: veredicto, qué corregir primero, hallazgos del peor al mejor con dónde, por qué y cómo corregir (el mismo problema en varios archivos aparece una vez, con todos los lugares), una nota de A a F y un distintivo. `--html ARCH` escribe también un informe en un solo archivo, para entregar o imprimir en PDF (en inglés o portugués): resumen, plan de corrección con el esfuerzo estimado, hallazgos con el fragmento de código (secretos enmascarados) y alcance y método.

Solo los nombres y versiones de los paquetes salen de tu máquina (a `api.osv.dev`, `www.cisa.gov`, `api.first.org` y `services.nvd.nist.gov`). Tu código nunca sale. Las respuestas se guardan en caché unas horas en `~/.cache/stingward`.

Stingward lee contenido hostil por diseño, así que lo trata con cuidado: git nunca descubre un repositorio dentro de los archivos auditados, los lanzadores nunca importan código de la carpeta auditada, y los secretos, los códigos de terminal y el markdown se neutralizan en todos los formatos. Ver [SECURITY.md](https://github.com/HiveControlAgents/StingWard/blob/main/SECURITY.md).

## GitHub Action

```yaml
# .github/workflows/stingward.yml
name: stingward
on:
  pull_request:
  push: { branches: [main] }
  schedule: [{ cron: "0 9 * * *" }]   # aparecen CVEs nuevas aunque el código no cambie
permissions: { contents: read, pull-requests: write, security-events: write }
jobs:
  stingward:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HiveControlAgents/StingWard@v0
        with: { lang: en, fail-on: high }
```

Comenta el informe en el PR (y actualiza el mismo comentario en cada ejecución), sube SARIF a la pestaña **Security** del repositorio, escribe el resumen del job y expone la nota en `steps.<id>.outputs.grade`.

| Entrada | Por defecto | |
|---|---|---|
| `path` | `.` | Carpeta a auditar |
| `fail-on` | `high` | Falla el job en esta severidad o mayor: `critical`, `high`, `medium`, `low`, `never` |
| `lang` | `en` | Idioma del informe: `en` o `pt` |
| `comment` | `true` | Comenta en los pull requests (necesita `pull-requests: write`) |
| `sarif` | `true` | Sube SARIF a code scanning (necesita `security-events: write` y, en repositorios privados, `actions: read`) |
| `category` | `stingward` | Categoría del SARIF en code scanning. Usa una distinta en cada ejecución cuando el mismo workflow audita varias carpetas |

## Referencia de la línea de comandos

| Opción | |
|---|---|
| `--lang en\|pt` | Idioma del informe (por defecto: `STINGWARD_LANG`, luego el idioma del sistema) |
| `--format text\|json\|markdown\|sarif\|html` | Qué va a la salida estándar |
| `--json ARCH`, `--markdown ARCH`, `--sarif ARCH`, `--html ARCH` | Escribe también estos archivos, en la misma ejecución |
| `--fail-on critical\|high\|medium\|low\|never` | Código de salida 1 en esta severidad o mayor (por defecto `high`) |
| `--only deps,secrets,app,code,agents` | Ejecuta solo algunas revisiones |
| `--offline` | No consulta las bases en línea (las dependencias no se revisan) |
| `--no-color` | Texto sin colores |
| `--review-template ARCH` | Escribe el archivo de la revisión humana: una entrada por hallazgo, conservando lo que ya se revisó |
| `--review ARCH` | Aplica la revisión humana: un estado y un comentario para cada hallazgo |
| `--client NOMBRE`, `--notes ARCH` | "Preparado para" en la portada y el resumen del analista (párrafos, listas con `-`, `**negrita**`, `` `código` ``) |

| Código de salida | Significado |
|---|---|
| `0` | Nada en la severidad de `--fail-on` o mayor |
| `1` | Se encontró algo en la severidad de `--fail-on` o mayor |
| `2` | Error de uso: una opción equivocada, una carpeta que no existe, un skill que no se pudo descargar o un archivo de salida que no se pudo escribir |
| `3` | OSV.dev no respondió y las dependencias no se revisaron, o respondió solo en parte y la revisión quedó incompleta. Un control de CI no debería pasar en silencio; usa `--offline` para saltarlas a propósito. |
| `4` | No se leyó ningún archivo, así que no había nada que calificar: carpeta vacía, ruta equivocada o, en CI, el código no se descargó antes (checkout). Un control de CI no debería pasar en silencio; `--fail-on never` lo acepta. |

Entorno: `STINGWARD_LANG` define el idioma por defecto, `NVD_API_KEY` sube el límite de consultas a NVD y `STINGWARD_CACHE` cambia la carpeta de caché.

**Nota:** A significa solo hallazgos bajos o ninguno · B medios, ningún alto · C uno o dos altos · D tres o más altos · F algún crítico. Cada informe termina con un distintivo para tu README:

```markdown
[![stingward: A](https://img.shields.io/badge/stingward-A-brightgreen)](https://github.com/HiveControlAgents/StingWard)
```

**Revisión humana:** para una auditoría que entregas a otra persona, escribe el archivo de revisión con `stingward . --review-template revision.json`. Cada entrada apunta a un hallazgo por su `fingerprint` (que también sale en el JSON y el SARIF), que no cambia cuando se editan otras partes del archivo. Se hace con la línea marcada y el secreto ya enmascarado, así que nada derivado de un secreto va al archivo de revisión. Es a propósito, y significa que una clave cambiada por otra en la misma línea conserva su estado: cuando se rote una clave, revisa esa línea de nuevo antes de reutilizar la revisión. Pon en `status` `confirmed`, `false_positive`, `accepted_risk` o `fixed`, escribe el `comment` y ejecuta `stingward . --review revision.json --client "Nombre del cliente" --notes notas.md --html informe.html`. Los falsos positivos pasan a un apéndice; ellos y lo que se corrigió durante la auditoría salen de la nota, de la lista de qué corregir primero y de `--fail-on`. Los riesgos aceptados siguen contando para la nota, pero salen de la lista de qué corregir primero. Los informes de texto y Markdown también siguen la revisión. Los comentarios y el resumen se escapan y pasan por el mismo enmascaramiento de secretos que los fragmentos de código. En una revisión hecha por una IA, pon `"review_kind": "ai"` en el archivo de revisión: los informes dicen revisión por IA en lugar de revisión humana, `accepted_risk` se rechaza (solo el cliente acepta un riesgo) y `fixed` solo se acepta para un hallazgo que desapareció de un escaneo que podía verlo: sin `.stingwardignore`, comentario `stingward:ignore` ni los límites de tamaño y de archivos ocultándolo.

**Falsos positivos:** agrega una línea a `.stingwardignore` en la raíz del proyecto (`REGLA ruta/glob`, `REGLA` o `ruta/glob`), o escribe `stingward:ignore` en un comentario en la línea. Si una regla está mal, [avísanos](https://github.com/HiveControlAgents/StingWard/issues/new?template=false-positive.yml) con un ejemplo mínimo.

**Estándares:** los hallazgos llevan identificadores **CWE**, **OWASP Top 10 para aplicaciones con LLM 2026** (`LLM01:2026`...), **OWASP Agentic Skills Top 10** (`AST01`..., borrador v1) y **OWASP Top 10 para aplicaciones agénticas 2026** (`ASI01`...), en el texto, el JSON y las etiquetas SARIF.

## Calidad

- **Más de 400 pruebas automáticas**, además de pruebas en línea que consultan de verdad OSV, KEV, EPSS y NVD en seis ecosistemas. La cobertura de líneas supera el 90%.
- **Cada push ejecuta 24 jobs de CI**: pruebas en Linux, macOS y Windows con Python 3.9 a 3.14, los paquetes de PyPI y npm construidos e instalados desde cero en los tres sistemas, el plugin de Claude Code validado y la Action ejecutada sobre proyectos de ejemplo.
- **Stingward se audita a sí mismo** en CI y no puede tener hallazgos altos ni críticos; su propia nota es el distintivo A de arriba.
- **Los falsos positivos se miden** en colecciones populares de skills y servidores MCP públicos: ningún hallazgo crítico o alto que no sea real, y pocos medios por repositorio. Cada falso positivo corregido se convierte en una prueba de regresión.
- **Revisión de seguridad del propio Stingward**, por ejemplo para asegurar que una carpeta de skill armada como repositorio git no ejecuta comandos, y que un secreto nunca llega a un informe. Cada problema encontrado se corrige con una prueba que falla en el código anterior.

```bash
python -m unittest discover -s tests -t .                       # sin red, unos segundos
STINGWARD_ONLINE=1 python -m unittest discover -s tests -t .    # también consulta las bases reales
```

## Preguntas frecuentes

**¿Un informe limpio significa que mi proyecto es seguro?** No. Significa que los errores más comunes no están. Stingward es una primera línea rápida, no una prueba de penetración.

**¿Mi código sale de mi máquina?** No. Solo se envían nombres y versiones de paquetes, para buscar vulnerabilidades.

**¿En qué se diferencia de `npm audit`, Dependabot o un escáner de secretos?** Cada uno cubre una parte. Stingward junta dependencias, secretos y los errores propios de apps hechas con IA, agentes, skills y servidores MCP en un solo informe, escrito para quien construyó el proyecto, y puede auditar una skill antes de que la instales.

**¿Por qué `npx stingward` necesita Python?** El motor es un único paquete de Python puro sin dependencias; el paquete de npm solo lo lanza, para que quien usa JavaScript lo ejecute sin `pip`. En Windows, `npx` no encuentra los atajos `.bat` de pyenv-win: instala Python desde python.org o usa `pip install stingward`.

**¿Puede revisar un repositorio privado o una skill en mi disco?** Sí. Apúntalo a una carpeta, o a `dueno/repo` con tus credenciales de git de siempre.

## Alcance

Stingward informa a quien lo ejecuta, sobre el código que esa persona eligió revisar. No recorre repositorios ajenos ni abre issues en ellos.

## Contribuir

Reportes de errores, falsos positivos y reglas nuevas son bienvenidos. Lee [CONTRIBUTING.md](https://github.com/HiveControlAgents/StingWard/blob/main/CONTRIBUTING.md) (en inglés) para preparar el entorno, y reporta los problemas de seguridad del propio Stingward en privado, como explica [SECURITY.md](https://github.com/HiveControlAgents/StingWard/blob/main/SECURITY.md).

Datos de vulnerabilidades: [OSV.dev](https://osv.dev) (que reúne GitHub Advisories, NVD, PyPA, RustSec, Go y los paquetes maliciosos de OpenSSF), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/) y [NVD](https://nvd.nist.gov).

[Apache 2.0](https://github.com/HiveControlAgents/StingWard/blob/main/LICENSE) © Isaque Moutta
