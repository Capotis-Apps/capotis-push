# Capotis Push - Servidor de Notificaciones para Capotis Mail

Servidor de notificaciones push auto-alojado para Capotis Mail. Sin Firebase. Sin Google. Tus correos no pasan por nadie.

Tú tienes tu dominio, tu Mailcow y tu servidor. Este programa es el que avisa a tu iPhone cuando te llega un correo nuevo.

## ¿Cómo funciona?

```
Mailcow recibe un correo
    ↓
Capotis Push lo ve por IMAP IDLE
    ↓
Capotis Push le dice a Apple (APNs) "avisa a este iPhone"
    ↓
Te llega la notificación a Capotis Mail
```

Tus correos nunca pasan por Capotis Apps, ni por Google, ni por nadie. Todo se queda en tu servidor.

## ¿Qué necesitas antes de empezar?

1. Un servidor donde correr Docker (tu propio VPS, un mini-PC en casa, donde tengas Mailcow)
2. Mailcow instalado y funcionando
3. Una cuenta de Apple Developer (99€/año) para generar tu clave .p8
4. Capotis Mail en tu iPhone

## Instalación rápida

```bash
git clone https://github.com/capotisapps/capotis-push.git
cd capotis-push
docker compose up -d
```

Al arrancar te dirá en qué puerto está corriendo. Por ejemplo:

```
Capotis Push corriendo en http://tu-servidor:7391
```

Entra a esa URL desde tu navegador.

## Configuración paso a paso

La interfaz web te guía paso a paso, pero aquí va el resumen:

### 1. Crea tu usuario
La primera vez que entras, crea un usuario y una contraseña. Esa misma contraseña la pondrás luego en Capotis Mail para conectar la app con este servidor.

### 2. Conecta Mailcow
Te pedirá la dirección de tu Mailcow y un buzón para comprobar que lo ve. Si lo ve, pasa al siguiente paso.

### 3. Sube tu clave .p8 de Apple
1. Entra a https://developer.apple.com/account/resources/authkeys/list
2. Crea una Key con el servicio APNs activado
3. Descarga el archivo `.p8`
4. En el panel de Capotis Push, dale a "Subir archivo .p8", selecciona el archivo
5. Pon tu Team ID y tu Key ID (te los da Apple en esa misma página)

Capotis Push comprobará que la clave es válida.

### 4. Conecta Capotis Mail
En tu iPhone, en Capotis Mail > Ajustes > Notificaciones > Activar:
- Pon la IP de tu servidor (por ejemplo por Tailscale: `100.78.183.61`)
- Pon el puerto (por ejemplo `7391`)
- Pon el usuario y contraseña que creaste en el paso 1
- Dale a "Probar conexión"

Si conecta, la app te pedirá permiso de notificaciones. Acéptalo y listo. Tu iPhone mandará su device token a tu servidor.

### 5. Manda una notificación de prueba
En el panel web, dale a "Mandar notificación de prueba". Te debe llegar una notificación a tu iPhone que dice "Capotis Push funciona".

Si da error, te mostrará el error en lenguaje simple y un botón "Ver error completo" para ver el detalle técnico.

## Puertos

Por defecto usa el puerto **7391**. Es un puerto raro a propósito, para que no te choque con otros programas. Puedes cambiarlo en `docker-compose.yml` si quieres.

## Seguridad

- Este servidor es TUYO. No manda nada a Capotis Apps.
- Tu clave .p8 nunca sale de tu servidor. No la subas a GitHub, no la compartas.
- Usa siempre HTTPS o Tailscale para conectar la app con el servidor. No lo expongas a internet sin contraseña.
- Cada usuario debe tener SU propia clave .p8, SU propio servidor y SU propio dominio. No uses la clave de otro.

## Licencia

Este proyecto es de código abierto, pero **NO es para ganar dinero con él**.

Puedes copiarlo, modificarlo y usarlo para ti y para tus amigos. No puedes venderlo, ni cobrar por él, ni subirlo como si fuera la versión oficial de Capotis Push.

Lee el archivo `LICENSE` para el texto completo.

## Contacto

- App: Capotis Mail por Capotis Apps
- Correo: contacto@capotisapps.com
- Web: https://omdorganization.com
