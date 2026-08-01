# cpp-dns-probe — DNS resolver & packet analyzer

Resolvedor y analizador de paquetes **DNS** escrito desde cero en **C++23** puro (solo biblioteca estándar + sockets POSIX). Implementa el formato wire de DNS (RFC 1035): codificación de nombres con compresión, cabeceras, questions y resource records (A, AAAA, CNAME, MX, NS, SOA, PTR, TXT), con transporte UDP propio, reintentos y medición de RTT.

## Características

- **Formato wire DNS implementado desde cero**: codificador de queries + parser de respuestas con compresión de nombres (punteros `0xC0`)
- **Tipos de registro**: A, AAAA, MX (preferencia), TXT (múltiples strings), NS, CNAME, PTR, SOA (mname/rname/serial/refresh/retry/expire/minimum)
- **Resolución UDP propia** con timeout, reintentos y medición de RTT — sin librerías externas
- **Reverse lookup** con `-x <ipv4>` (PTR sobre `in-addr.arpa`)
- **Múltiples dominios** en una sola invocación
- **Decodificación offline** con `--parse <hex>` — analiza respuestas capturadas sin red
- **Self-test** (`--selftest`): 10 casos de encode/decode/parse, incluyendo una respuesta real capturada de 8.8.8.8
- Servidor por defecto desde `/etc/resolv.conf` (fallback 8.8.8.8), configurable con `--server`/`--port`
- Salida con colores ANSI (auto-detecta TTY, `--no-color` para scripts)
- Exit codes estándar: `0` = respuestas encontradas, `1` = NXDOMAIN / sin registros, `2` = error

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o dnsprobe
```

Requiere GCC 14+ (usa `std::println`, `std::print`, `std::from_chars`). Solo dependencias del sistema: sockets POSIX.

## Uso

```bash
# Resolver A (por defecto)
./dnsprobe example.com

# Otros tipos
./dnsprobe gmail.com --type MX
./dnsprobe google.com --type AAAA
./dnsprobe wikipedia.org --type NS
./dnsprobe example.com --type TXT

# Varios dominios
./dnsprobe example.com wikipedia.org

# Reverse lookup
./dnsprobe -x 8.8.8.8

# Resolver específico y timeout
./dnsprobe example.com --server 1.1.1.1 --timeout 5 --retries 3

# Decodificar una respuesta capturada (offline)
./dnsprobe --parse "$(cat sample-response.hex)"

# Self-tests
./dnsprobe --selftest
```

## Ejemplo

```
$ ./dnsprobe example.com
dnsprobe — DNS resolver & packet analyzer (C++23)

  ▸ example.com  (A)  → 127.0.0.11:53  [timeout 3s ×3]
  id=0xFB0E  flags: QR RD RA   rcode: NOERROR
  question:  example.com  IN  A
  answer: 2  authority: 0  additional: 0  · 61 bytes
      ── ANSWER (2)
        example.com  300  IN  A  172.66.147.243
        example.com  300  IN  A  104.20.23.154
      ✓ 2 answer(s) in 7.8 ms
```

## Estructura

```
src/main.cpp        # Todo el proyecto: wire format DNS + CLI (monolítico, stdlib-only)
sample-response.hex # Respuesta real capturada de 8.8.8.8 para demo de --parse
dnsprobe            # Binario compilado
```
