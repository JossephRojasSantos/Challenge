# Define la imagen base
FROM golang:latest

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos del proyecto al directorio de trabajo en el contenedor
COPY . .

# Descarga las dependencias del módulo Go
RUN go mod download

# Compila la aplicación
RUN go build -o main

# Expone el puerto en el que la aplicación escucha
EXPOSE 443
EXPOSE 80
EXPOSE 8080

# Define el comando de inicio de la aplicación
CMD ["./main"]

ENV host=
ENV port=
ENV user=
ENV passworddb=
ENV dbname=
ENV passwordadmin=
ENV changepass=
ENV jwtkey=