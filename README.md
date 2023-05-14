# Challenge

## Resumen:

Se ha desarrollado una API en lenguaje Go que se encarga de obtener información de clientes desde un proveedor externo. Esta API procesa y trata los datos para generar disponibilidad, permitiendo que la información sea accesible para los distintos sectores dentro de la empresa, garantizando un acceso controlado y eficiente al contenido

### Pasos Iniciales:
======
#### Entorno Windows con Docker
------
1. Descargar e instalar PostgresSQL ->  [PostgresSQL](https://get.enterprisedb.com/postgresql/postgresql-10.23-1-windows.exe)
2. Confirmar puerto de servicio **[port]**
3. Crear Base de Datos **[dbname]**
4. Generar usuario de lectura y escritura en la base de datos *[dbname]* creada en el punto 3 **[user][pass]**
5. Descargar e instalar Docker -> [Docker](https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe)
6. Modificar la sección **IPv4 local connections:** del archivo **pg_hba.conf** de la base de datos, ingresando la IP de Origen definida en el Contenedor.
7. Reiniciar servicio de PostgresSQL. 
8. Ingresar los siguientes datos en las variables **ENV** ubicadas en el archivo **Dockerfile**
* ENV host=[IP del equipo donde se ejecuta el servicio PostgresSQL]
* ENV port=[port]-> Definido en el punto 2
* ENV user=[user]-> Definido en el punto 4
* ENV passworddb=[pass]-> Definido en el punto 4
* ENV dbname=[dbname]-> Definido en el punto 3
* ENV passwordadmin=[passadmin]-> Contraseña en sha512
* ENV changepass=1-> Cuando se encuentra con valor 0, cambia la contraseña de passwordadmin 
* ENV jwtkey=[jwtkey]-> Contaseña para la firma de token de sesión

![](https://github.com/JossephRojasSantos/Challenge/blob/main/png/ENVDockerFile.png)

8. Descargamos el presente repositorio, nos ubicamos con un CMD en el proyecto e ingresamos los siguientes comandos:
```javascript
docker build -t servidor:Challenge .
```
```javascript
docker run -p 8080:8080 -p 443:443 -p 80:80 servidor:Challenge
```
9. Ingresamos en Docker Desktop y verificamos que en **Containers** nuestra imagen tenga estado **Running**
10. Ingresamos por medio de un navegador a **https://localhost/**

#### Entorno Windows sin Docker
------
1. Descargar e instalar PostgresSQL ->  [PostgresSQL](https://get.enterprisedb.com/postgresql/postgresql-10.23-1-windows.exe)
2. Confirmar puerto de servicio **[port]**
3. Crear Base de Datos **[dbname]**
4. Generar usuario de lectura y escritura en la base de datos **[dbname]** creada en el punto 3 **[user][pass]**
5. Descargar e instalar Go -> [GO](https://dl.google.com/go/go1.20.4.windows-amd64.msi)
6. Comprobar instalacion de Go (desde un CMD ejecutar "go version", retorno de la consola -> go version go1.20.4 windows/amd64)
7. Crear las siguiente variables de entorno:

* host=localhost
* port=[port]-> Definido en el punto 2
* user=[user]-> Definido en el punto 4
* passworddb=[pass]-> Definido en el punto 4
* dbname=[dbname]-> Definido en el punto 3
* passwordadmin=[passadmin]-> Contraseña en sha512
* jwtkey=[jwtkey]-> Contaseña para la firma de token de sesión
* Changepass=1 -> Cuando se encuentra con valor 0, cambia la contraseña de passwordadmin 


![](https://github.com/JossephRojasSantos/Challenge/blob/main/png/Variables%20de%20Entorno.png)

8. Descargamos el presente repositorio, nos ubicamos con un CMD en el proyecto e ingresamos el siguiente comando:
```javascript
go build main.go
```
9. Dentro de la carpeta del proyecto, ubicamos y ejecutamos como administrador el archivo **main.exe**.    
10. Ingresamos por medio de un navegador a **https://localhost/**