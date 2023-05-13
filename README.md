# Challenge

Resumen:
Se ha desarrollado una API en lenguaje Go que se encarga de obtener información de clientes desde un proveedor externo. Esta API procesa y trata los datos para generar disponibilidad, permitiendo que la información sea accesible para los distintos sectores dentro de la empresa, garantizando un acceso controlado y eficiente al contenido

Pasos Iniciales:

Entorno (Windows) sin Docker
1. Descargar e instalar PostgresSQL ->  https://get.enterprisedb.com/postgresql/postgresql-10.23-1-windows.exe
2. Confirmar puerto de servicio [port]
3. Crear Base de Datos [dbname]
4. Generar usuario de lectura y escritura en la base de datos [dbname] creada en el punto 3 [user][pass]
5. Descargar e instalar Go -> https://dl.google.com/go/go1.20.4.windows-amd64.msi
6. Comprobar instalacion de Go (desde un CMD ejecutar "go version", retorno de la consola -> go version go1.20.4 windows/amd64)
7. Crear las siguiente variables de entorno:
	 host=localhost
	 port=[port]-> Definido en el punto 2
	 user=[user]-> Definido en el punto 4
	 passworddb=[pass]-> Definido en el punto 4
	 dbname=[dbname]-> Definido en el punto 3
	 passwordadmin=[passadmin]-> Contraseña en sha512
	 jwtkey=[jwtkey]-> Contaseña para la firma de token de sesión


![Ejemplo de variable de entorno](https://github.com/JossephRojasSantos/Challenge/blob/main/png/Variables%20de%20Entorno.png){width='100px'}