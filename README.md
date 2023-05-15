# Challenge

## Resumen:

Se ha desarrollado una API en lenguaje Go que se encarga de obtener información de clientes desde un proveedor externo. Esta API procesa y trata los datos para generar disponibilidad, permitiendo que la información sea accesible para los distintos sectores dentro de la empresa, garantizando un acceso controlado y eficiente al contenido.

![](https://github.com/JossephRojasSantos/Challenge/blob/main/png/Diagrama%20-%20Arquitectura.png)


![](https://github.com/JossephRojasSantos/Challenge/blob/main/png/Diagrama.png)
### Pasos Iniciales:
------
#### Entorno Windows con Docker

1. Descargar e instalar PostgreSQL ->  [PostgreSQL](https://get.enterprisedb.com/postgresql/postgresql-10.23-1-windows.exe)
2. Confirmar puerto de servicio **[port]**
3. Crear Base de Datos **[dbname]**
4. Generar usuario de lectura y escritura en la base de datos *[dbname]* creada en el punto 3 **[user][pass]**
5. Descargar e instalar Docker -> [Docker](https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe)
6. Modificar la sección **IPv4 local connections:** del archivo **pg_hba.conf** de la base de datos, ingresando la IP de Origen definida en el Contenedor.
7. Reiniciar servicio de PostgreSQL. 
8. Ingresar los siguientes datos de variables de entorno **ENV** ubicadas en el archivo **Dockerfile**

* ENV host=[IP del equipo donde se ejecuta el servicio PostgreSQL]
* ENV port=[port]-> Definido en el punto 2
* ENV user=[user]-> Definido en el punto 4
* ENV passworddb=[pass]-> Definido en el punto 4
* ENV dbname=[dbname]-> Definido en el punto 3
* ENV passwordadmin=[passadmin]-> Contraseña en sha512
* ENV changepass=1-> Cuando se encuentra con valor 0, cambia la contraseña de passwordadmin 
* ENV jwtkey=[jwtkey]-> Contraseña para la firma de token de sesión

![](https://github.com/JossephRojasSantos/Challenge/blob/main/png/ENVDockerFile.png)

8. Descargamos el presente repositorio, nos ubicamos con un CMD en el proyecto e ingresamos los siguientes comandos:
```docker
docker build -t servidor:Challenge .
```
```docker
docker run -p 8080:8080 -p 443:443 -p 80:80 servidor:Challenge
```
9. Ingresamos en Docker Desktop y verificamos que en **Containers** nuestra imagen tenga estado **Running**
10. Ingresamos por medio de un navegador a **https://localhost/**
------
#### Entorno Windows sin Docker

1. Descargar e instalar PostgreSQL ->  [PostgreSQL](https://get.enterprisedb.com/postgresql/postgresql-10.23-1-windows.exe)
2. Confirmar puerto de servicio **[port]**
3. Crear Base de Datos **[dbname]**
4. Generar usuario de lectura y escritura en la base de datos **[dbname]** creada en el punto 3 **[user][pass]**
5. Descargar e instalar Go -> [GO](https://dl.google.com/go/go1.20.4.windows-amd64.msi)
6. Comprobar instalación de Go (desde un CMD ejecutar "go version", retorno de la consola -> go version go1.20.4 windows/amd64)
7. Crear las siguiente variables de entorno:

* host=localhost
* port=[port]-> Definido en el punto 2
* user=[user]-> Definido en el punto 4
* passworddb=[pass]-> Definido en el punto 4
* dbname=[dbname]-> Definido en el punto 3
* passwordadmin=[passadmin]-> Contraseña en sha512
* jwtkey=[jwtkey]-> Contraseña para la firma de token de sesión
* Changepass=1 -> Cuando se encuentra con valor 0, cambia la contraseña de passwordadmin 


![](https://github.com/JossephRojasSantos/Challenge/blob/main/png/Variables%20de%20Entorno.png)

8. Descargamos el presente repositorio, nos ubicamos con un CMD en el proyecto e ingresamos el siguiente comando:
```go
go build main.go
```
9. Dentro de la carpeta del proyecto, ubicamos y ejecutamos como administrador el archivo **main.exe**.    
10. Ingresamos por medio de un navegador a **https://localhost/**

**Nota:** Es necesario ejercutar el binario como administrador (Punto 9) para obterner los valores de las variables de entorno configuradas en windows

### Modo de Operación 

------
#### Administrador

Rol con capacidad para crear o eliminar usuarios que accedan o consuman el aplicativo. El presente usuario accede por la Web con las siguientes credenciales:

* Usuario=administrator
* Contraseña= (Definida en las variables de entorno como **passwordadmin**)
* OTP= (Extraer de la base de datos **userdata**, columna **tokenmfa**)

------
#### Usuario

Rol de solo lectura con capacidad para visualizar los datos externos consumidos. El presente usuario accede por la Web con las siguientes credenciales:

* Usuario= (Definido e informado por el administrador)
* Contraseña= (Definido e informado por el administrador)
* OTP= (Informado por el administrador)

------
#### Desarrollador o API

Rol de solo lectura con capacidad para visualizar los datos externos consumidos. Este usuario obtiene los datos en formato JSON bajo la siguiente URL:

```html
https://localhost:8080/json?username=[usuario]&token=[token]
```

* [token]= (Método de autenticación (JWT) informado por el administrador, utiliza el parámetro jwtkey definida en las variable de entorno)
* [usuario]= (Datos de usuario a consultar)
