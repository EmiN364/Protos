# Protocolo de Comunicación

## Introducción
Este proyecto desarrolla dos protocolos de comunicación: SMTP y un Protocolo de Monitoreo, implementados por el Grupo 4 para la asignatura "72.07 - Protocolos de Comunicación".

## Integrantes
- Candisano Gonzalo (Legajo: 62616)
- Gonzalez Rouco Lucas (Legajo: 63366)
- Neme Emilio Pablo (Legajo: 62601)
- Shlamovitz Theo (Legajo: 62087)

## Profesores
- Codagnone Juan Francisco
- Garberoglio Marcelo Fabio
- Kulesz Sebastian

## Protocolo SMTP
- **Función**: Envío de correos electrónicos.
- **Comandos**: HELO, EHLO, MAIL FROM, RCPT TO, DATA, QUIT.
- **Implementación**: C con sockets y threads.

## Protocolo de Monitoreo
- **Función**: Consulta y modificación de estadísticas vía UDP.
- **Mensaje**: 14 bytes de longitud fija.
- **Seguridad**: Autenticación con token de 8 bytes.
- **Cliente**: Aplicación UDP.

## Compilación
Para compilar el proyecto, ejecutar el siguiente comando:
```bash
user@machine:path/ $  make all
```

## Uso del servidor
```bash
 ./smtpd
```
Default Password is: `secretpa`
```bash
 ./smtpd -u mipass23

```
```bash
 ./smtpd -u mipass23 -P 2626 -p 2525 -T tac

```

## Uso del cliente
```bash
 ./mng_client <Server Address/Name> <Auth> <Server Port/Service> <Command>
```