# NTD - Network Threat Detection

NTD es una herramienta de línea de comandos en Python que lee un `conn.log` de [Zeek](https://zeek.org/) en formato JSON lines y ordena las conexiones de red por lo inusuales que son, usando un **Isolation Forest** (aprendizaje no supervisado). Marca las más extremas y explica en qué se desvían.

Es un proyecto de aprendizaje y portafolio con un alcance deliberadamente acotado: funciona **offline**, sobre **un solo archivo** y con **features numéricas**. No necesita datos etiquetados ni un modelo previo: el modelo se ajusta sobre el propio archivo que analizas.

> **Qué significa "flagged".** Como el modelo se ajusta y puntúa sobre el mismo archivo, `flagged` marca siempre la fracción superior por score (`--contamination`), también en tráfico completamente limpio. No es un veredicto de ataque. La señal útil es el **ranking** (`anomaly_score`) y las **razones** (`reasons`).

## Contenido

1. [Cómo funciona](#cómo-funciona)
2. [Instalación](#instalación)
3. [Uso rápido y salida real](#uso-rápido-y-salida-real)
4. [Referencia del CLI](#referencia-del-cli)
5. [Formato de entrada](#formato-de-entrada)
6. [Features](#features)
7. [Detector y `flagged`](#detector-y-flagged)
8. [Explicabilidad (`reasons`)](#explicabilidad-reasons)
9. [Modo por host (`--by-host`)](#modo-por-host---by-host)
10. [Salida](#salida)
11. [Datos sintéticos y evaluación](#datos-sintéticos-y-evaluación)
12. [Tests](#tests)
13. [Estructura del repositorio](#estructura-del-repositorio)
14. [Limitaciones](#limitaciones)
15. [Fuera de alcance](#fuera-de-alcance)

## Cómo funciona

```
conn.log (JSON lines)
        │
        ▼
  loader.py      lee y valida registros, cuenta las filas saltadas
        │
        ▼
  features.py    9 features numéricas
        │
        ▼
  detector.py    Isolation Forest → score + marca de la fracción superior
        │
        ├──► explain.py   razones por conexión (z-score robusto)
        ▼
  report.py      ordena, escribe el CSV y arma el resumen
        │
        ▼
  cli.py         orquesta todo y gestiona errores / códigos de salida

  hosts.py       (opcional, --by-host) agrega por IP de origen y puntúa cada host
```

| Módulo | Responsabilidad |
|---|---|
| `ntd/loader.py` | `load_conn_log(path)` devuelve `(DataFrame, skipped)`. Tolera líneas sucias y valida puertos. |
| `ntd/features.py` | `build_features(df)` devuelve el `DataFrame` de features, conservando el índice. |
| `ntd/detector.py` | `detect(features, contamination, random_state, n_estimators, max_samples, n_jobs)` devuelve `(scores, flags)`. |
| `ntd/explain.py` | `explain(features, top_n, rows)` devuelve el texto de razones por fila. |
| `ntd/report.py` | `build_results`, `write_csv` y `format_summary`. |
| `ntd/hosts.py` | `build_host_table`, `analyze_hosts`, `write_hosts_csv`, `format_host_summary`. |
| `ntd/cli.py` | Punto de entrada `ntd analyze`. |

## Instalación

Requisitos: Python **3.10 o superior**. Dependencias de runtime: `pandas>=2.0`, `numpy>=1.24` y `scikit-learn>=1.3`. El extra `dev` añade `pytest>=7`.

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

Esto instala el comando `ntd`.

## Uso rápido y salida real

Con los datos sintéticos incluidos (se regeneran con `tests/synthetic.py`):

```bash
.venv/bin/python tests/synthetic.py tests/data/sample_conn.json
.venv/bin/ntd analyze tests/data/sample_conn.json --top 4
```

Salida real (semilla fija, reproducible):

```
Rows read: 2130
Rows valid: 2130
Rows skipped: 0
Flagged: 22 (1.03%) - top fraction by score, not a verdict
Top 4 most suspicious connections:
          ts id.orig_h  id.orig_p   id.resp_h  id.resp_p proto anomaly_score                                              reasons
1700020000.0  10.0.0.7      45000 203.0.113.9        443   tcp        0.7545 bytes_ratio +77.7; orig_bytes +13.8; orig_pkts +13.1
1700020001.0  10.0.0.7      45001 203.0.113.9        443   tcp        0.7545 bytes_ratio +77.7; orig_bytes +13.8; orig_pkts +13.1
1700020002.0  10.0.0.7      45002 203.0.113.9        443   tcp        0.7545 bytes_ratio +77.7; orig_bytes +13.8; orig_pkts +13.1
1700020003.0  10.0.0.7      45003 203.0.113.9        443   tcp        0.7545 bytes_ratio +77.7; orig_bytes +13.8; orig_pkts +13.1
Wrote 22 rows to anomalies.csv
```

Con tu propio log de Zeek (activa antes el formato JSON con `@load policy/tuning/json-logs`):

```bash
.venv/bin/ntd analyze conn.log --contamination 0.01 --out anomalies.csv --top 10
```

También se puede ejecutar como módulo: `python -m ntd.cli analyze conn.log`.

## Referencia del CLI

```
ntd analyze INPUT [--contamination F] [--out RUTA] [--top N] [--all]
                  [--n-estimators N] [--max-samples M] [--n-jobs J] [--seed S]
                  [--by-host] [--hosts-out RUTA]
```

`analyze` es el único subcomando y es obligatorio.

| Argumento | Default | Descripción |
|---|---|---|
| `INPUT` (posicional) | n/a | Ruta al `conn.log` en JSON lines. |
| `--contamination` | `0.01` | Fracción de conexiones a marcar, en (0, 0.5]. Se marcan exactamente `ceil(contamination · n)` filas. |
| `--out` | `anomalies.csv` | Ruta del CSV. Se crean los directorios padre si faltan. |
| `--top` | `10` | Cuántas conexiones marcadas imprimir. Entero ≥ 0; con `0` solo se muestran los conteos. |
| `--all` | desactivado | Escribe en el CSV todas las conexiones (y calcula `reasons` para todas), no solo las marcadas. |
| `--n-estimators` | `100` | Número de árboles. Entero > 0. |
| `--max-samples` | `auto` | Filas por árbol: `auto`, un entero > 0 (sin punto) o un decimal en (0, 1]. |
| `--n-jobs` | `1` | Trabajos en paralelo; `-1` usa todos los núcleos. No puede ser `0`. |
| `--seed` | `42` | Semilla aleatoria. Misma semilla, mismo resultado. |
| `--by-host` | desactivado | Además puntúa cada IP de origen (ver [Modo por host](#modo-por-host---by-host)). |
| `--hosts-out` | `hosts.csv` | Ruta del CSV por host, usada con `--by-host`. |

Códigos de salida:

| Código | Significado |
|---|---|
| `0` | Éxito. |
| `1` | Error de ejecución: archivo inexistente o vacío, sin registros válidos, `--contamination` o `--max-samples` fuera de rango, o error al escribir un CSV. El mensaje sale por stderr como `error: ...`. |
| `2` | Argumentos inválidos rechazados por argparse (por ejemplo `--top -1`, `--n-estimators 0` o `--max-samples lots`). |

## Formato de entrada

Una línea JSON por conexión. Se aceptan claves planas con punto (`"id.orig_h"`) y el objeto anidado `"id": {...}`.

```json
{"ts": 1700000000.0, "id.orig_h": "10.0.0.32", "id.orig_p": 46687, "id.resp_h": "10.0.1.10", "id.resp_p": 8080, "proto": "tcp", "duration": 0.0396, "orig_bytes": 448, "resp_bytes": 1567, "orig_pkts": 40, "resp_pkts": 73, "conn_state": "SF"}
```

**Campos obligatorios:** `ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`. Una fila a la que le falte alguno, o donde sea `null`, `"-"` o `""`, se salta y se cuenta en `Rows skipped`.

**Puerto destino:** `id.resp_p` debe ser numérico y estar en [0, 65535]. Un valor no numérico o mayor que 65535 salta la fila (ya no se imputa a 0). El puerto `0` también salta la fila cuando `proto` es `tcp` o `udp`; en ICMP se conserva, porque Zeek guarda ahí el tipo/código ICMP y `0` es habitual.

**Campos numéricos opcionales:** `id.orig_p`, `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`. Si faltan, valen `-`/`null`, no son numéricos o son negativos, se imputan a `0`.

**Conteos del resumen:** `Rows read = Rows valid + Rows skipped`. Las líneas en blanco no cuentan. Saltan y se cuentan: JSON mal formado, valores que no son objeto (como `[1,2,3]`) y filas con campos obligatorios o puerto inválidos.

**Errores:** archivo inexistente (`Input file not found`), archivo vacío (`Input file is empty`) y archivo sin ninguna fila válida (`No valid connection records found in input`).

El archivo se carga entero en memoria; el loader solo conserva las columnas que usa para reducir el pico. El formato TSV por defecto de Zeek **no** está soportado.

## Features

`features.py` produce 9 features por conexión:

| Feature | Cálculo |
|---|---|
| `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts` | `log1p` de cada columna |
| `bytes_ratio` | `log1p(orig_bytes / (resp_bytes + 1))` |
| `port_wellknown` | 1 si el puerto destino es < 1024 |
| `port_registered` | 1 si es < 49152 y ≥ 1024 |
| `port_ephemeral` | 1 si es ≥ 49152 |

Las tres de puerto son un one-hot: son categorías, no puntos de una escala. Se usa `log1p` porque bytes, paquetes y duración tienen colas muy pesadas. `proto`, `conn_state` y las IPs **no** se usan como features por conexión.

## Detector y `flagged`

`detector.py` envuelve `sklearn.ensemble.IsolationForest` (parámetros expuestos por el CLI; `contamination` se valida en (0, 0.5]).

- El modelo se ajusta y puntúa sobre los mismos datos.
- `anomaly_score = -score_samples(features)`: **cuanto más alto, más sospechosa** es la conexión.
- `flagged` marca exactamente las `ceil(contamination · n)` filas con mayor score (los empates se resuelven por orden del archivo). Se hace por ranking y no con el umbral interno de scikit-learn, porque este no marca las filas empatadas en el corte: con bloques de sondas idénticas (por ejemplo un escaneo) marcaría muchas menos filas de las esperadas.
- Si todos los scores son idénticos no se marca ninguna fila.
- Es **determinista** para una misma semilla.

## Explicabilidad (`reasons`)

La columna `reasons` lista hasta 3 desviaciones, p. ej. `bytes_ratio +77.7; orig_bytes +13.8; orig_pkts +13.1`.

- Features continuas: z-score robusto `(x − mediana) / (1.4826 · MAD)` en espacio log, con un piso de 0.1 para la escala; solo se listan las que superan `|z| ≥ 3`.
- Clases de puerto: si la conexión pertenece a una clase que tiene menos del 5% de las filas, aparece `rare port class (...)`.
- Si nada destaca por sí solo, el texto es `no strong single-feature deviation`.
- Se calcula solo para las filas marcadas (o para todas con `--all`).

**Es una descripción, no el razonamiento del modelo**: indica cuánto se aleja la fila de lo típico del archivo, no el camino interno del bosque. Dos features que se combinan de forma rara sin que ninguna sea extrema pueden dar score alto y no tener razones.

## Modo por host (`--by-host`)

Por defecto no cambia nada. Con `--by-host` se agrega por `id.orig_h` y un segundo Isolation Forest (mismos parámetros del modelo) puntúa cada host. Sirve para ver lo que una conexión suelta no muestra: escaneos (muchos puertos o destinos) y comportamiento periódico.

| Columna | Significado |
|---|---|
| `n_conns` | Conexiones del host |
| `n_dst_hosts` | Destinos distintos |
| `n_dst_ports` | Puertos destino distintos |
| `bytes_sent` | Suma de `orig_bytes` |
| `min_pair_iat_cv` | Mínimo coeficiente de variación de los intervalos entre conexiones al mismo (destino, puerto) con ≥ 5 eventos. Bajo = periódico (indicio de beaconing). Si ningún par llega a 5 eventos vale `1.0` (neutral); tope 5.0. |

Salida: `hosts.csv` con `host_score`, `flagged` y `reasons`, ordenado por score. Ejemplo real (`--contamination 0.05 --by-host`):

```
Hosts analysed: 53
Hosts flagged: 3
Top 3 most suspicious source hosts:
id.orig_h  n_conns  n_dst_hosts  n_dst_ports  bytes_sent min_pair_iat_cv host_score                                               reasons
10.0.0.99        5            1            5           0            1.00     0.7577     bytes_sent -37.3; n_conns -10.0; n_dst_hosts -6.9
10.0.0.98       80            1           80           0            1.00     0.7533 bytes_sent -37.3; n_dst_ports +26.0; n_dst_hosts -6.9
 10.0.0.7       52            4            5  2500052794            0.00     0.7351                bytes_sent +42.6; min_pair_iat_cv -3.5
Wrote 3 rows to hosts.csv
```

En ese mismo log el host `10.0.0.55` hace beaconing exacto cada 50 s, pero con solo 3 hosts marcados queda en el cuarto lugar y no sale en la lista: con contaminación baja el beaconing se puede quedar fuera. Si hay menos de 10 hosts se imprime una advertencia por stderr, porque el modelo tiene poca potencia estadística.

## Salida

### CSV por conexión

Cabecera: `ts,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,anomaly_score,flagged,reasons`

- Ordenado por `anomaly_score` descendente.
- Por defecto solo contiene las filas con `flagged=True`. Con `--all` contiene todas.

```
1700020000.0,10.0.0.7,45000,203.0.113.9,443,tcp,0.7544679805795973,True,bytes_ratio +77.7; orig_bytes +13.8; orig_pkts +13.1
```

### Resumen en terminal

Muestra `Rows read`, `Rows valid`, `Rows skipped`, `Flagged` y la tabla de las conexiones marcadas (`--top`). Si no se marca nada aparece `No connections flagged.`. La tabla solo lista filas marcadas, aunque `--top` sea mayor que el número marcado.

## Datos sintéticos y evaluación

`tests/synthetic.py` genera un log reproducible:

- **2000 conexiones normales** (por defecto): puertos 80, 443, 53, 22 y 8080, tres servidores `10.0.1.10-12` y 50 clientes `10.0.0.1-50`.
- **Port scan** y **exfiltración** (5 filas cada uno). `difficulty="easy"` usa ataques descarados; `"hard"` usa un escaneo lento con sondas pequeñas y una exfiltración de 300 KB.
- `hard_negatives=True` añade tráfico legítimo pero inusual (descargas grandes y sesiones ssh largas) que **no** se etiqueta como ataque.
- `beacon=True` y `wide_scan=True` añaden un host con callbacks cada 50 s y otro que sondea 80 puertos; son para `--by-host` y no entran en las etiquetas.
- `n_attack=0` genera un archivo limpio de control.

```bash
python tests/synthetic.py [salida]    # por defecto tests/data/sample_conn.json (incluye beacon y wide_scan)
```

**Evaluación sintética de sanidad (no es un benchmark).** `tests/test_evaluation.py` calcula ROC-AUC y recall@k con las etiquetas del generador, sobre varias semillas. Resultados al fijar los umbrales (semillas 0-7):

| Escenario | ROC-AUC | recall@k |
|---|---|---|
| Fondo limpio, `easy` y `hard` | 1.00 | 1.00 |
| Con tráfico legítimo inusual (`hard_negatives`) | ≈ 0.99 | ≈ 0.50 |

El modelo separa bien estos ataques sintéticos del tráfico simulado, incluso con la versión sutil. Lo que le cuesta es distinguir exfiltración de descargas legítimas enormes o de sesiones ssh largas: compiten por los primeros puestos. El test de control sobre tráfico limpio comprueba que `flagged` marca igualmente el 1% (por eso no es un veredicto) y que el score de los ataques supera el máximo del tráfico limpio.

## Tests

```bash
.venv/bin/pytest
```

| Archivo | Qué cubre |
|---|---|
| `test_smoke.py` | El paquete se importa. |
| `test_loader.py` | Claves planas y anidadas, imputación a 0, validación de puertos (tcp/udp con 0, ICMP con 0, no numérico, > 65535), líneas en blanco, mal formadas o incompletas, errores de archivo. |
| `test_features.py` | Columnas y orden, `log1p`, `bytes_ratio`, one-hot de puerto, fila de ceros finita, índice preservado. |
| `test_detector.py` | Outlier con score máximo, determinismo y semilla, parámetros inválidos, conteo exacto de `flagged`, empates, una fila y datos constantes. |
| `test_explain.py` | Orden y signo de las razones, MAD cero sin `inf`/`nan`, clase de puerto rara, `top_n`, subconjunto de filas. |
| `test_report.py` | Orden y columnas, CSV solo marcadas o completo, conteos del resumen, `reasons`. |
| `test_hosts.py` | Agregación por host, coeficiente de variación periódico vs irregular, ranking en el log sintético, advertencia con pocos hosts. |
| `test_cli.py` | CSV ordenado y resumen, `--all`, errores y códigos de salida, flags del modelo, `--by-host`. |
| `test_evaluation.py` | ROC-AUC, recall@k, tráfico legítimo inusual y control negativo. |
| `test_end_to_end.py` | Smoke test: los ataques descarados quedan en el top 1%. |

## Estructura del repositorio

```
.
├── pyproject.toml
├── README.md
├── docs/superpowers/
│   ├── specs/    2026-10-08-ntd-mvp-design.md, 2026-10-15-ntd-v0.2-design.md
│   └── plans/    2026-10-08-ntd-mvp.md, 2026-10-15-ntd-v0.2.md
├── ntd/
│   ├── cli.py  detector.py  explain.py  features.py
│   └── hosts.py  loader.py  report.py
└── tests/
    ├── synthetic.py
    ├── data/sample_conn.json
    └── test_*.py
```

El diseño y el plan de cada versión están en `docs/superpowers/`.

## Limitaciones

- El modelo se ajusta y puntúa sobre el mismo archivo. No hay modelo persistente ni evaluación con datos etiquetados reales.
- `flagged` marca siempre `ceil(contamination · n)` filas, incluso en tráfico limpio. El score es comparable dentro de un archivo, no como veredicto.
- La validación es solo sobre datos sintéticos, y el modelo confunde con facilidad exfiltración con descargas legítimas grandes.
- `reasons` describe desviaciones respecto a la mediana del archivo, no el razonamiento interno del bosque.
- `--by-host` tiene poca potencia con pocos hosts, no usa ventanas temporales y no detecta bien beaconing con jitter alto. Un solo par (destino, puerto) periódico basta para bajar `min_pair_iat_cv`.
- Imputar `0` en los numéricos opcionales hace indistinguible un valor ausente de un `0` real.
- El archivo se carga entero en memoria y el bosque se ajusta con todas las filas (o `--max-samples` por árbol). No hay lectura por bloques.
- Solo JSON lines, sin TSV.

## Fuera de alcance

Suricata `eve.json`, evaluación con datasets etiquetados (por ejemplo CIC-IDS), modelos guardados y reutilizados, streaming, lectura por bloques, reportes HTML, dashboards y alertas.
