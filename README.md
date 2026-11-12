# Larascan

![Rust](https://img.shields.io/badge/Rust-1.85%2B%20(Edition%202024)-orange?logo=rust)
![Target](https://img.shields.io/badge/Target-Laravel%20(PHP%20%26%20Blade)-red?logo=laravel)
![Output](https://img.shields.io/badge/Formatos-Consola%20%7C%20JSON%20%7C%20SARIF-blue)

**Larascan** es un analizador estático de seguridad y estándares de código para proyectos **Laravel**, escrito en Rust. Utiliza **Tree-sitter** para inspeccionar el árbol de sintaxis abstracta (AST) de archivos PHP y analiza plantillas Blade línea por línea.

> **Aviso importante:** Los hallazgos generados por Larascan son **indicadores que requieren revisión manual**, no pruebas definitivas de que exista una vulnerabilidad explotable.

---

## Tabla de contenidos

- [Requisitos](#requisitos)
- [Compilación y pruebas](#compilación-y-pruebas)
- [Uso](#uso)
- [Alcance del análisis](#alcance-del-análisis)
- [Catálogo de reglas](#catálogo-de-reglas)
- [Supresiones](#supresiones)
- [Integración en CI](#integración-en-ci)
- [Estructura del proyecto](#estructura-del-proyecto)

---

## Requisitos

Para compilar Larascan desde el código fuente necesitas:

- **Rust y Cargo** con soporte para la **edición 2024** (`Rust 1.85` o posterior).
- **Compilador de C** compatible con tu *toolchain* de Rust (requerido para compilar las gramáticas de Tree-sitter).
  - **Windows (MSVC):** requiere tener instaladas las *Herramientas de compilación de C++ de Visual Studio*.

---

## Compilación y pruebas

Ejecuta los siguientes comandos desde la raíz del repositorio:

```bash
# Compilar binario optimizado
cargo build --release

# Ejecutar suite de pruebas
cargo test
```

- **Ubicación del ejecutable:**
  - **Linux / macOS:** `target/release/larascan`
  - **Windows:** `target\release\larascan.exe`
- El archivo `Cargo.lock` se mantiene versionado en el repositorio para garantizar compilaciones reproducibles.

---

## Uso

Indica la ruta raíz del proyecto Laravel mediante `--path` (o `-p`). Si omites este argumento, Larascan analizará el directorio actual.

### Ejemplos en Linux y macOS

*(Asumiendo que `larascan` se encuentra en tu `PATH`)*

```bash
# Reporte legible en consola
larascan --path /ruta/al/proyecto

# Exportar reporte en formato JSON
larascan --path /ruta/al/proyecto --json > reporte.json

# Exportar reporte en formato SARIF
larascan --path /ruta/al/proyecto --sarif > larascan-results.sarif

# Fallar el comando si existen hallazgos altos o críticos
larascan --path /ruta/al/proyecto --fail-on-high
```

### Ejemplo en Windows (PowerShell)

```powershell
.\target\release\larascan.exe --path 'C:\laragon\www\mi-proyecto' --json |
    Set-Content -Encoding utf8 reporte.json
```

### Referencia de opciones y códigos de salida

| Flag | Descripción |
| :--- | :--- |
| `-p`, `--path <RUTA>` | Ruta raíz del proyecto Laravel a analizar (por defecto: `.`). |
| `--json` | Emite los resultados en formato JSON por salida estándar. |
| `--sarif` | Emite los resultados en formato SARIF (prevalece si se combina con `--json`). |
| `--fail-on-high` | Finaliza con código de salida `1` si se detectan hallazgos de severidad **Alta** o **Crítica**. |
| `-h`, `--help` | Muestra la ayuda completa con todas las opciones disponibles. |

| Código de salida | Significado |
| :---: | :--- |
| `0` | Análisis completado sin errores (y sin hallazgos altos/críticos si se usó `--fail-on-high`). |
| `1` | Se detectaron hallazgos altos/críticos (con `--fail-on-high`) o ocurrió un error al recorrer, leer o analizar archivos. |

---

## Alcance del análisis

- **Archivos analizados:** Todos los archivos con extensión `.php` (incluidas las vistas `.blade.php`) dentro de la raíz indicada y sus subdirectorios.
- **Directorios excluidos:**
  - `vendor`, `storage`, `node_modules` y `.git` en cualquier nivel.
  - `bootstrap/cache`.
- **Enlaces simbólicos:** No se siguen durante el recorrido de directorios, salvo que la ruta raíz proporcionada en `--path` sea en sí misma un enlace simbólico a un directorio.
- **Codificación:** Todos los archivos analizados deben ser UTF-8 válidos.
- **Validación de reglas:** Las consultas de Tree-sitter se compilan al iniciar la ejecución; cualquier error en la definición de una regla se reporta explícitamente en lugar de omitirse en silencio.

---

## Catálogo de reglas

### Seguridad (`SEC`)

| ID | Severidad | Patrón detectado |
| :--- | :---: | :--- |
| `SEC-001` | Alta | Llamadas a métodos `raw`, `whereRaw`, `selectRaw`, `orderByRaw` o `havingRaw`. |
| `SEC-002` | Crítica | Llamadas a `eval`, `exec`, `passthru`, `shell_exec`, `system` y ejecución mediante comillas invertidas (`` `...` ``). |
| `SEC-003` | Alta | Literales asignados a variables con nombres asociados a claves, secretos, contraseñas o tokens. |
| `SEC-004` | Alta | Impresión Blade sin escapar con `{!! ... !!}` en una misma línea. |
| `SEC-005` | Media | Propiedad `$guarded` inicializada con un arreglo vacío (`[]`). |
| `SEC-006` | Crítica | Llamadas a `unserialize()`. |

### Estándares y calidad (`STD`)

| ID | Severidad | Patrón detectado |
| :--- | :---: | :--- |
| `STD-001` | Media | Uso de `env()` fuera del directorio `config/` de la raíz del proyecto. |
| `STD-002` | Baja | Ausencia de una declaración inicial `declare(strict_types=1);`. |
| `STD-003` | Baja | Llamadas a funciones de depuración (`dd`, `dump`, `var_dump` o `ray`). |

### Consideraciones y privacidad

- **Sin análisis de flujo de datos (*taint analysis*):** Las reglas AST distinguen nodos de código PHP frente a comentarios y cadenas de texto, pero no rastrean si una variable proviene de entrada controlada por un atacante.
- **Heurísticas por nombre:** `SEC-005` detecta propiedades llamadas `$guarded` sin verificar si la clase hereda de un modelo Eloquent; `SEC-003` se basa en patrones de nombres y no garantiza la detección de todos los secretos posibles.
- **Análisis textual en Blade:** Las vistas `.blade.php` se evalúan línea por línea, por lo que pueden señalarse ocurrencias dentro de comentarios Blade o pasarse por alto expresiones `{!! ... !!}` distribuidas en varias líneas.
- **Manejo de reportes:** Las salidas de consola y JSON incluyen fragmentos de código fuente que podrían contener credenciales o información sensible. Revisa y protege los reportes antes de compartirlos.

---

## Supresiones

Puedes ignorar un hallazgo puntual añadiendo un comentario con `larascan-ignore` seguido del ID de la regla en la **misma línea** del hallazgo o en la **línea inmediatamente anterior**.

### En archivos PHP

```php
// larascan-ignore STD-003
dd($debugData);

$users = DB::raw('SELECT * FROM users'); // larascan-ignore SEC-001
```

### En vistas Blade

```blade
{{-- larascan-ignore SEC-004 --}}
{!! $trustedHtml !!}
```

> **Nota sobre `STD-002`:** Dado que esta regla se reporta en la primera línea del archivo, su comentario de supresión (`// larascan-ignore STD-002`) debe colocarse en esa misma primera línea.

---

## Integración en CI

Con el ejecutable de Larascan disponible en el *runner*, puedes exportar resultados en formato SARIF y hacer fallar el *pipeline* si existen hallazgos altos o críticos:

```bash
larascan --path . --sarif --fail-on-high > larascan-results.sarif
```

### Recomendaciones para el *pipeline*

1. Configura el paso de subida o publicación del archivo `larascan-results.sarif` para que se ejecute **incluso si el paso de análisis falla** (por ejemplo, usando `if: always()` en GitHub Actions).
2. Verifica que los permisos de acceso y las rutas del reporte SARIF sean adecuados para la visibilidad de tu repositorio antes de publicarlos.

---

## Estructura del proyecto

```text
larascan/
├── .gitignore
├── Cargo.toml
├── Cargo.lock
├── src/
│   ├── main.rs       # CLI, recorrido de archivos y procesamiento paralelo
│   ├── models.rs     # Definición de argumentos y tipos de datos
│   ├── rules.rs      # Catálogo de reglas y compilación de consultas AST
│   ├── scanner.rs    # Motor de análisis para PHP y vistas Blade
│   └── reporter.rs   # Generadores de reportes (consola, JSON y SARIF)
└── tests/
    └── scan_scope.rs # Pruebas de alcance de análisis y formatos de salida
```

El archivo `.gitignore` excluye artefactos de compilación, configuraciones locales de editores y los nombres de reportes de ejemplo, sin eliminar archivos existentes ni dejar de rastrear archivos ya versionados en Git.
