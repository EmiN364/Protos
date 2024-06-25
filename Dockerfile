# Usa la imagen base de Ubuntu
FROM ubuntu:latest

# Información del mantenedor
LABEL maintainer="lgonzalezrouco@itba.edu.ar"

# Actualiza el sistema e instala las herramientas necesarias
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    gdb \
    netcat \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Crea un directorio de trabajo
WORKDIR /root

# Copia el código fuente al contenedor (opcional, si deseas copiar algo en la construcción)
# COPY . .

# Comando por defecto para ejecutar cuando el contenedor se inicie
CMD ["/bin/bash"]
