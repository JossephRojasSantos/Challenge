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

ENV host=192.168.1.195
ENV port=5432
ENV user=postgres
ENV passworddb=Holacomoestan30*
ENV dbname=challenge
ENV passwordadmin=cf18911a66fd7bacee91e5505063e6afe0d71de7e657aec7ea3b6c6966318a78313f4bbf6a81d4a5ec278ec4529bd2c9a3a75cee0fe253465779e56e99ff6138
ENV changepass=1
ENV jwtkey=69wmj66fw8plcpe72jtd