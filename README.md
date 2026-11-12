# Larascan

Larascan es un analizador estático para proyectos Laravel, escrito en Rust. Utiliza
Tree-sitter para buscar patrones en archivos PHP y revisa las vistas Blade línea
por línea. Sus hallazgos son **indicadores que requieren revisión**, no pruebas
de que exista una vulnerabilidad.

## Requisitos

- Rust y Cargo con soporte para la edición 2024 (Rust 1.85 o posterior).
- Una herramienta de compilación de C compatible con el entorno de Rust, necesaria
  para Tree-sitter. En Windows con Rust MSVC se necesitan las herramientas de
  compilación de C++ de Visual Studio.

## Compilación y pruebas

Desde el directorio de Larascan:

```bash
cargo build --release
cargo test
```

El ejecutable se genera en `target/release/larascan` en Linux y macOS, o
`target\release\larascan.exe` en Windows. El archivo `Cargo.lock` se conserva
para reproducir las dependencias de la aplicación.

## Uso

Indica la raíz del proyecto Laravel con `--path` (o `-p`). Si no se especifica,
se utiliza el directorio actual. Los siguientes ejemplos suponen que `larascan`
está en el `PATH`:

```bash
# Reporte en consola
larascan --path /ruta/al/proyecto

# Reporte JSON
larascan --path /ruta/al/proyecto --json > reporte.json

# Reporte SARIF
larascan --path /ruta/al/proyecto --sarif > larascan-results.sarif

# Fallar si hay hallazgos altos o críticos
larascan --path /ruta/al/proyecto --fail-on-high
```

En PowerShell, por ejemplo:

```powershell
.\target\release\larascan.exe --path 'C:\laragon\www\mi-proyecto' --json |
    Set-Content -Encoding utf8 reporte.json
```

Usa `--help` para consultar todas las opciones. Si se indican `--sarif` y `--json`
simultáneamente, se produce SARIF. `--fail-on-high` termina con código 1 cuando
hay hallazgos de severidad alta o crítica; los errores al recorrer, leer o analizar
archivos también terminan con código 1.

### Alcance del análisis

Se buscan archivos con extensión `.php`, incluidas vistas `.blade.php`, en la
raíz indicada y sus subdirectorios. Se excluyen `vendor`, `storage`,
`node_modules` y `.git` en cualquier nivel, y los directorios `cache` dentro de
`bootstrap`. No se siguen enlaces simbólicos durante el recorrido, salvo que
la ruta inicial sea un enlace a un directorio.

Los archivos deben poder leerse como UTF-8. Las consultas de las reglas se
compilan al inicio y se notifica cualquier error, en lugar de omitir una regla
silenciosamente.

## Reglas

| ID | Patrón detectado | Severidad |
| --- | --- | --- |
| SEC-001 | Llamadas a métodos `raw`, `whereRaw`, `selectRaw`, `orderByRaw` o `havingRaw` | Alta |
| SEC-002 | `eval`, `exec`, `passthru`, `shell_exec`, `system` y ejecución con comillas invertidas | Crítica |
| SEC-003 | Literales asignados a variables con nombres relacionados con claves, secretos, contraseñas o tokens | Alta |
| SEC-004 | Impresión Blade sin escapar con `{!! ... !!}` en una misma línea | Alta |
| SEC-005 | Una propiedad `$guarded` inicializada con un arreglo vacío | Media |
| SEC-006 | Llamadas a `unserialize()` | Crítica |
| STD-001 | Uso de `env()` fuera del directorio `config` de la raíz | Media |
| STD-002 | Falta de una declaración inicial `declare(strict_types=1)` | Baja |
| STD-003 | Llamadas a `dd`, `dump`, `var_dump` o `ray` | Baja |

Las reglas AST distinguen nodos PHP de comentarios y texto, pero no realizan
análisis de flujo de datos. Por ejemplo, usar SQL raw o `unserialize()` no
demuestra que los datos sean controlados por un atacante. SEC-005 detecta
propiedades llamadas `$guarded` sin verificar si su clase es un modelo Eloquent;
SEC-003 no detecta todos los posibles secretos. El análisis de Blade es textual:
puede señalar comentarios y no detecta expresiones distribuidas en varias líneas.

Los reportes de consola y JSON incluyen fragmentos de código, que pueden
contener información sensible. Revisa y protege los reportes antes de compartirlos.

### Supresiones

Para ignorar una regla concreta, incluye `larascan-ignore` seguido de su ID en
la misma línea del hallazgo o en la línea anterior:

```php
// larascan-ignore STD-003
dd($debugData);

$users = DB::raw('SELECT * FROM users'); // larascan-ignore SEC-001
```

En Blade también se puede usar un comentario:

```blade
{{-- larascan-ignore SEC-004 --}}
{!! $trustedHtml !!}
```

Para STD-002, cuya ubicación es la primera línea del archivo, la supresión debe
estar en esa línea.

## Integración en CI

Con el ejecutable ya disponible en el runner, se puede generar SARIF y hacer
fallar el paso si hay hallazgos altos o críticos:

```bash
larascan --path . --sarif --fail-on-high > larascan-results.sarif
```

La subida del reporte debe configurarse para ejecutarse incluso si ese paso falla.
Antes de publicarlo, verifica que la configuración de acceso y las rutas del reporte
sean apropiadas para tu proyecto.

## Estructura

```text
larascan/
├── .gitignore
├── Cargo.toml
├── Cargo.lock
├── src/
│   ├── main.rs       # CLI, recorrido y procesamiento paralelo
│   ├── models.rs     # Argumentos y tipos de datos
│   ├── rules.rs      # Reglas y compilación de consultas AST
│   ├── scanner.rs    # Análisis PHP y Blade
│   └── reporter.rs   # Reportes de consola y SARIF
└── tests/
    └── scan_scope.rs # Pruebas de alcance y formatos
```

El `.gitignore` excluye compilaciones, configuración local de editores y los
nombres de reportes de ejemplo. No elimina archivos existentes ni deja de
rastrear archivos que ya estén en Git.
