#!/bin/bash

# Nombre de la imagen y del contenedor
IMAGE_NAME="protos_image"
CONTAINER_NAME="protos"

# Verifica si la imagen ya existe
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]]; then
    # Construye la imagen desde el Dockerfile
    docker build -t $IMAGE_NAME .
else
    echo "La imagen $IMAGE_NAME ya existe. No es necesario construirla de nuevo."
fi

# Verifica si el contenedor ya existe
if [ ! "$(docker ps -a -q -f name=$CONTAINER_NAME)" ]; then
    # Crea el contenedor desde la imagen
    docker run -d -v ${PWD}:/root --security-opt seccomp:unconfined -ti --name $CONTAINER_NAME $IMAGE_NAME
else
    echo "El contenedor $CONTAINER_NAME ya existe."
fi

# Inicia el contenedor si no está corriendo
if [ ! "$(docker ps -q -f name=$CONTAINER_NAME)" ]; then
    docker start $CONTAINER_NAME
else
    echo "El contenedor $CONTAINER_NAME ya está corriendo."
fi

# Entra al contenedor
docker exec -it $CONTAINER_NAME bash

exit
