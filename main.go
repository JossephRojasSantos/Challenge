package main

import (
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/pquerna/otp/totp"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
)

var (
	host                      = os.Getenv("host")
	port                      = os.Getenv("port")
	user                      = os.Getenv("user")
	password                  = os.Getenv("passworddb")
	dbname                    = os.Getenv("dbname")
	passwordadmin             = os.Getenv("passadministrator")
	changepass                = os.Getenv("changepass")
	jwtkey                    = []byte(os.Getenv("jwtkey"))
	psqlInfo                  = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	useradmin                 = "administrator"
	jsonview                  []Jsonview
	data                      []Data
	table                     = Table{}
	userview                  = User{}
	userviewtable             []User
	arraytable                []Table
	arraytable2               []Table
	url                       = "https://62433a7fd126926d0c5d296b.mockapi.io/api/v1/usuarios"
	tmpl                      = template.Must(template.ParseGlob("template/*"))
	ID                        int
	FecAlta                   string
	UserName                  string
	CodigoZip                 string
	CreditCardNum             string
	HashCreditCardNum         string
	CreditCardCcv             string
	HashCreditCardCcv         string
	CuentaNumero              string
	Direccion                 string
	GeoLatitud                string
	GeoLongitud               string
	ColorFavorito             string
	FotoDni                   string
	Ip                        string
	Auto                      string
	AutoModelo                string
	AutoTipo                  string
	AutoColor                 string
	CantidadComprasRealizadas int
	Avatar                    string
	FecBirthday               string
	userSecrets               = make(map[string]string)
	filePathKEY               string
	filePathCERT              string
	whitelist                 []string
	TokenMFA                  string
	Rol                       int
	RolClaim                  string
)

type Data struct {
	FecAlta                   string    `json:"fec_alta"`
	UserName                  string    `json:"user_name"`
	CodigoZip                 string    `json:"codigo_zip"`
	CreditCardNum             string    `json:"credit_card_num"`
	CreditCardCcv             string    `json:"credit_card_ccv"`
	CuentaNumero              string    `json:"cuenta_numero"`
	Direccion                 string    `json:"direccion"`
	GeoLatitud                string    `json:"geo_latitud"`
	GeoLongitud               string    `json:"geo_longitud"`
	ColorFavorito             string    `json:"color_favorito"`
	FotoDni                   string    `json:"foto_dni"`
	Ip                        string    `json:"ip"`
	Auto                      string    `json:"auto"`
	AutoModelo                string    `json:"auto_modelo"`
	AutoTipo                  string    `json:"auto_tipo"`
	AutoColor                 string    `json:"auto_color"`
	CantidadComprasRealizadas int       `json:"cantidad_compras_realizadas"`
	Avatar                    string    `json:"avatar"`
	FecBirthday               time.Time `json:"fec_birthday"`
	Id                        string    `json:"id"`
}
type Jsonview struct {
	FecAlta                   string `json:"fec_alta"`
	UserName                  string `json:"user_name"`
	HashcreditcardnumSha512   string `json:"HashCreditCardNum_SHA512"`
	HashcreditcardccvSha512   string `json:"HashCreditCardCcv_SHA512"`
	CuentaNumero              string `json:"cuenta_numero"`
	GeoLatitud                string `json:"geo_latitud"`
	GeoLongitud               string `json:"geo_longitud"`
	Ip                        string `json:"ip"`
	CantidadComprasRealizadas int    `json:"cantidad_compras_realizadas"`
}
type Table struct {
	ID                        int
	FecAlta                   string
	UserName                  string
	CodigoZip                 string
	CreditCardNum             string
	HashCreditCardNum         string
	CreditCardCcv             string
	HashCreditCardCcv         string
	CuentaNumero              string
	Direccion                 string
	GeoLatitud                string
	GeoLongitud               string
	ColorFavorito             string
	FotoDni                   string
	Ip                        string
	Auto                      string
	AutoModelo                string
	AutoTipo                  string
	AutoColor                 string
	CantidadComprasRealizadas int
	Avatar                    string
	FecBirthday               string
}
type User struct {
	IDuser   int
	UserName string
	TokenMFA string
	Rol      int
}

func Err(err2 error) {
	if err2 != nil {
		log.Println(err2)
	}
}
func ConexionDB() (db *sql.DB) {
	db, err := sql.Open("postgres", psqlInfo)
	log.Println("Conectando con Base de Datos")
	Err(err)
	return db
}
func Ofuscar(str string, num int) (s string) {
	s = str
	s = strings.ReplaceAll(s, "-", "")                   // Eliminar el carácter "-"
	s = strings.Repeat("*", len(s)-num) + s[len(s)-num:] // Reemplazar con "*"
	//log.Println("Ocultando Datos con *")
	return s
}
func Hash(str string) (s string) {
	hash := sha512.Sum512([]byte(str))
	s = hex.EncodeToString(hash[:])
	//log.Println("Generando Hash SHA512")
	return s
}
func RemoverCaracteresEspeciales(input string) (output string) {
	c := input
	regex := regexp.MustCompile("[^a-zA-Z0-9._-]+")
	output = regex.ReplaceAllString(c, "")
	log.Println("Removiendo Caracteres Especiales")
	return output
}
func GenerarSessionCookie(s string, r string) (*http.Cookie, error) {

	value, err := GenerarTokenJWT(s, r)
	Err(err)
	cookie := &http.Cookie{
		Name:     "Authorization",
		Value:    value,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		Expires:  time.Now().Add(15 * time.Minute), // Tiempo de expiración de la cookie en segundos
	}

	log.Println("Cookie Generada")
	return cookie, nil
}
func GenerarTokenJWT(username string, rol string) (string, error) {
	// Crear un nuevo token JWT
	token := jwt.New(jwt.SigningMethodHS256)

	// Configurar los claims (datos del usuario)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["role"] = rol
	claims["exp"] = time.Now().Add(15 * time.Minute).Unix()

	tokenString, err := token.SignedString(jwtkey)
	Err(err)
	log.Println("Token JWT Generado")
	return tokenString, nil
}
func Login(writer http.ResponseWriter, request *http.Request) {
	if request.Method == "POST" {
		username := request.FormValue("username")
		password := request.FormValue("password")
		mfa := request.FormValue("mfa")
		log.Printf("Usuario Ingresado: %s", username)
		passwordhash := Hash(password)
		passwordhashdb, tokenMFA, roluser := ConsultarTablaUsuarios(username)

		validoOTP := VerificarOTP(tokenMFA, mfa)

		if (passwordhash == passwordhashdb) && validoOTP {
			cookie, err := GenerarSessionCookie(username, roluser)
			if roluser == "1" {
				http.SetCookie(writer, cookie)
				Err(err)
				http.Redirect(writer, request, "/viewuser", http.StatusSeeOther)
				log.Printf("Inicio de Sesion Correcto de: %s", username)
				return
			} else if roluser == "3" {
				http.SetCookie(writer, cookie)
				Err(err)
				http.Redirect(writer, request, "/inicio", http.StatusSeeOther)
				log.Printf("Inicio de Sesion Correcto de: %s", username)
				return
			}
		}
		http.Error(writer, "Nombre de usuario, contraseña o token incorrectos", http.StatusUnauthorized)
		log.Println("Nombre de usuario, contraseña o token incorrectos")
		return
	}
	_ = tmpl.ExecuteTemplate(writer, "login", nil)
}
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {

		//tokenString := request.Header.Get("Authorization")
		tokenString, err := request.Cookie("Authorization")
		log.Println("Obteniendo Cookie")

		if err != nil || tokenString.Value == "" {
			if request.URL.Path != "/" {
				http.Redirect(writer, request, "/", http.StatusSeeOther)
				log.Println("Redirigir por no tener Token JWT")
				return
			}
		} else {
			// Verificar si el token es válido

			token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token) (interface{}, error) {
				// Verificar si el algoritmo de firma es válido
				log.Println("Verificando")
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("método de firma inválido: %v", token.Header["alg"])
					log.Println("Metodo de firma de Token JWT invalido")
				}
				return jwtkey, nil
			})
			if err != nil {
				// Si el token no es válido, redirigir a la página de inicio de sesión
				http.Redirect(writer, request, "/", http.StatusSeeOther)
				log.Println("Token JWT Invalido")
				return
			}
			if !token.Valid {
				// Si el token no es válido, redirigir a la página de inicio de sesión
				http.Redirect(writer, request, "/", http.StatusSeeOther)
				log.Println("Token JWT Invalido")
				return
			}
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				log.Println("No se pudo obtener el claim de rol")
			}

			RolClaim, ok = claims["role"].(string)
			if !ok {
				log.Println("No se pudo obtener el claim de rol")
			}
			log.Printf("Rol: %s", RolClaim)
		}
		// Si el usuario está autenticado, continuar con la siguiente ruta
		next.ServeHTTP(writer, request)

		log.Println("Siguiente Pagina")
	})
}
func whitelistMiddleware(next http.Handler, whitelist []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteIP := ObtenerIP(r)
		log.Printf("IP Remota: %s", remoteIP)
		if !VerificarIPenWhiteList(remoteIP, whitelist) {
			http.Error(w, "Acceso no autorizado", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
func generateSecretKey(userID string) (string, error) {
	secretKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "YourApp",
		AccountName: userID,
	})
	Err(err)

	userSecrets[userID] = secretKey.Secret()
	secretKey.Secret()
	log.Println("Key Secret OTP Generada")
	return secretKey.Secret(), nil
}
func VerificarOTP(secretKey, otpCode string) bool {
	valid := totp.Validate(otpCode, secretKey)
	if !valid {
		return false
		//goland:noinspection GoUnreachableCode,GoUnreachableCode,GoUnreachableCode
		log.Println("OTP Invalido")
	}
	log.Println("OTP Valido")
	return true
}
func redirectToHttps(writer http.ResponseWriter, request *http.Request) {
	http.Redirect(writer, request, "https://localhost:443"+request.RequestURI, http.StatusMovedPermanently)
	log.Println("Redireccion a HTTPS")
}
func main() {

	file, err := os.OpenFile("events.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	Err(err)
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	log.SetOutput(file)

	ObtenerDatos()
	CrearTablaUsuarios()
	CrearTablaDatos()
	InsertarDatos()
	Certificados()

	r := mux.NewRouter()
	r.Use(authMiddleware)
	r2 := mux.NewRouter()

	r.HandleFunc("/", Login)
	r.HandleFunc("/inicio", Inicio)
	r.HandleFunc("/info", Informacion)
	r2.HandleFunc("/json", Json)
	r.HandleFunc("/viewuser", VerUsuario)
	r.HandleFunc("/createuser", CrearUsuario)
	r.HandleFunc("/borrar", BorrarUsuario)

	go func() {
		_ = http.ListenAndServeTLS(":8080", filePathCERT, filePathKEY, whitelistMiddleware(r2, whitelist))
	}()
	log.Println("Servidor Corriendo")
	go func() {
		_ = http.ListenAndServeTLS(":443", filePathCERT, filePathKEY, r)
	}()
	_ = http.ListenAndServe(":80", http.HandlerFunc(redirectToHttps))

}
func ObtenerDatos() {
	resp, err := http.Get(url)
	Err(err)
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := ioutil.ReadAll(resp.Body)
	Err(err)
	log.Printf("Captura de datos de la URL %s", url)
	err = json.Unmarshal(body, &data)
	Err(err)
}
func CrearTablaDatos() {
	db := ConexionDB()
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	log.Println("Creando (si no existe) la tabla datos")
	createTableQuery := `CREATE TABLE IF NOT EXISTS datos (
                            id SERIAL PRIMARY KEY,
                            FecAlta TEXT,    
							UserName TEXT,   
							CodigoZip TEXT,    
							CreditCardNum TEXT,
							HashCreditCardNum TEXT,
							CreditCardCcv TEXT,
							HashCreditCardCcv TEXT, 
							CuentaNumero TEXT,    
							Direccion TEXT,   
							GeoLatitud TEXT,    
							GeoLongitud TEXT,  
							ColorFavorito TEXT,   
							FotoDni TEXT,  
							Ip TEXT,    
							Auto TEXT,    
							AutoModelo TEXT,    
							AutoTipo TEXT,    
							AutoColor TEXT,    
							CantidadComprasRealizadas INT,      
							Avatar TEXT,    
							FecBirthday TEXT
                         );`

	_, err := db.Exec(createTableQuery)
	Err(err)
}
func CrearTablaUsuarios() {
	db := ConexionDB()
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	log.Println("Creando (si no existe) la tabla userdata")
	createTableQuery := `CREATE TABLE IF NOT EXISTS userdata (
                            id SERIAL PRIMARY KEY, 
							username TEXT,   
							password TEXT,
							tokenmfa TEXT,
							rol INT    
							);`
	_, err := db.Exec(createTableQuery)
	Err(err)

	var dbuser string
	var Username string
	row, err := db.Query("Select username From userdata where rol=1")
	if row != nil {
		for row.Next() {
			err := row.Scan(&Username)
			Err(err)
		}
	}
	dbuser = fmt.Sprintf(Username)
	log.Printf("Insertando datos de %s si no existen en la tabla userdata", useradmin)
	if dbuser != useradmin {
		tokenmfa, err := generateSecretKey(useradmin)
		Err(err)
		query := fmt.Sprintf("INSERT INTO userdata (username,password,tokenmfa,rol) VALUES ('%s','%s','%s',1)",
			useradmin, passwordadmin, tokenmfa)
		_, err = db.Exec(query)
		log.Printf("Creando: %s", useradmin)
		Err(err)
	}
	if changepass == "0" {
		query := fmt.Sprintf("UPDATE userdata SET password='%s' WHERE username='%s'", passwordadmin, useradmin)
		log.Printf("Cambiando contraseña de: %s", useradmin)
		_, err := db.Exec(query)
		Err(err)
	}

}
func CrearUsuario(writer http.ResponseWriter, request *http.Request) {
	if RolClaim == "1" {
		if request.Method == "POST" {
			db := ConexionDB()
			defer func(db *sql.DB) {
				_ = db.Close()
			}(db)
			username := request.FormValue("username")
			password := request.FormValue("password")
			rol := request.FormValue("rol")
			passwordhash := Hash(password)
			log.Println("Insertando data en la tabla userdata")

			tokenmfa, err := generateSecretKey(username)
			Err(err)
			query := fmt.Sprintf("INSERT INTO userdata (username,password,tokenmfa,rol) VALUES ('%s','%s','%s','%s')",
				username, passwordhash, tokenmfa, rol)
			_, err = db.Exec(query)
			log.Printf("Creando: %s", username)
			Err(err)

		}
		_ = tmpl.ExecuteTemplate(writer, "createuser", nil)
	} else {
		http.Error(writer, "401 Unauthorized", http.StatusUnauthorized)
		log.Println("Acceso no autorizado a la pagina Inicio")
	}
}
func VerUsuario(writer http.ResponseWriter, _ *http.Request) {
	if RolClaim == "1" {
		db := ConexionDB()
		defer func(db *sql.DB) {
			_ = db.Close()
		}(db)
		log.Println("Consultando Usuarios")

		userviewtable = nil
		registros, err := db.Query("Select id,username,tokenmfa,rol  From userdata")
		Err(err)
		for registros.Next() {
			err = registros.Scan(&ID, &UserName, &TokenMFA, &Rol)
			Err(err)
			userview.IDuser = ID
			userview.UserName = UserName
			userview.TokenMFA = TokenMFA
			userview.Rol = Rol
			userviewtable = append(userviewtable, userview)

		}
		_ = tmpl.ExecuteTemplate(writer, "viewuser", userviewtable)
	} else {
		http.Error(writer, "401 Unauthorized", http.StatusUnauthorized)
		log.Println("Acceso no autorizado a la pagina Inicio")
	}
}
func BorrarUsuario(writer http.ResponseWriter, request *http.Request) {
	if RolClaim == "1" {
		idDato := request.URL.Query().Get("id")
		usuarioborrado := request.URL.Query().Get("user")
		db := ConexionDB()
		defer func(db *sql.DB) {
			_ = db.Close()
		}(db)
		if idDato != "1" {
			_, err := db.Query("DELETE FROM userdata where id = $1", idDato)
			Err(err)
			log.Printf("Usuario %s Borrado", usuarioborrado)
			http.Redirect(writer, request, "https://localhost/viewuser", http.StatusMovedPermanently)
		}
	} else {
		http.Error(writer, "401 Unauthorized", http.StatusUnauthorized)
		log.Println("Acceso no autorizado a la pagina Inicio")
	}
}
func ConsultarTablaUsuarios(u string) (p string, t string, r string) {
	db := ConexionDB()
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	output := RemoverCaracteresEspeciales(u)

	var PassUser string
	var TokenMFA string

	log.Printf("Obteniendo datos Pass y OTP de: %s", output)
	row, err := db.Query("Select password,tokenmfa,rol From userdata where username=$1", output)
	Err(err)
	if row != nil {
		for row.Next() {
			err := row.Scan(&PassUser, &TokenMFA, &Rol)
			Err(err)
		}
	}
	p = fmt.Sprintf(PassUser)
	t = fmt.Sprintf(TokenMFA)
	r = fmt.Sprintf(strconv.Itoa(Rol))

	return p, t, r
}
func InsertarDatos() {

	db := ConexionDB()
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	_, err := db.Exec("DELETE FROM datos")
	Err(err)
	log.Println("Insertando data en la tabla datos")
	//Se itera a traves de los datos y se insertan en la tabla
	for _, values := range data {

		CreditCardNum := Ofuscar(values.CreditCardNum, 4)
		CreditCardCcv := Ofuscar(values.CreditCardCcv, 1)

		HashCreditCardNum := Hash(strings.ReplaceAll(values.CreditCardNum, "-", ""))
		HashCreditCardCcv := Hash(values.CreditCardCcv)

		query := fmt.Sprintf("INSERT INTO datos (fecalta,username,codigozip,creditcardnum,hashcreditcardnum,creditcardccv,hashcreditcardccv,cuentanumero,direccion,geolatitud,geolongitud,colorfavorito,fotodni,ip,auto,automodelo,autotipo,autocolor,cantidadcomprasrealizadas,avatar,fecbirthday) VALUES ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',%d,'%s','%s')",
			values.FecAlta,
			values.UserName,
			values.CodigoZip,
			CreditCardNum,
			HashCreditCardNum,
			CreditCardCcv,
			HashCreditCardCcv,
			values.CuentaNumero,
			values.Direccion,
			values.GeoLatitud,
			values.GeoLongitud,
			values.ColorFavorito,
			values.FotoDni,
			values.Ip,
			values.Auto,
			values.AutoModelo,
			values.AutoTipo,
			values.AutoColor,
			values.CantidadComprasRealizadas,
			values.Avatar,
			values.FecBirthday)

		_, err := db.Exec(query)
		Err(err)

	}

}
func Inicio(writer http.ResponseWriter, _ *http.Request) {
	if RolClaim == "3" {
		db := ConexionDB()
		defer func(db *sql.DB) {
			_ = db.Close()
		}(db)

		registros, err := db.Query("Select * From datos")
		Err(err)
		log.Println("Pagina de Inicio")
		for registros.Next() {
			err = registros.Scan(&ID, &FecAlta, &UserName, &CodigoZip, &CreditCardNum, &HashCreditCardNum, &CreditCardCcv, &HashCreditCardCcv, &CuentaNumero, &Direccion, &GeoLatitud, &GeoLongitud, &ColorFavorito, &FotoDni, &Ip, &Auto, &AutoModelo, &AutoTipo, &AutoColor, &CantidadComprasRealizadas, &Avatar, &FecBirthday)
			Err(err)
			table.ID = ID
			table.FecAlta = FecAlta
			table.UserName = UserName
			table.CodigoZip = CodigoZip
			table.CreditCardNum = CreditCardNum
			table.HashCreditCardNum = HashCreditCardNum
			table.CreditCardCcv = CreditCardCcv
			table.HashCreditCardCcv = HashCreditCardCcv
			table.CuentaNumero = CuentaNumero
			table.Direccion = Direccion
			table.GeoLatitud = GeoLatitud
			table.GeoLongitud = GeoLongitud
			table.ColorFavorito = ColorFavorito
			table.FotoDni = FotoDni
			table.Ip = Ip
			table.Auto = Auto
			table.AutoModelo = AutoModelo
			table.AutoTipo = AutoTipo
			table.AutoColor = AutoColor
			table.CantidadComprasRealizadas = CantidadComprasRealizadas
			table.Avatar = Avatar
			table.FecBirthday = FecBirthday

			arraytable = append(arraytable, table)

		}

		_ = tmpl.ExecuteTemplate(writer, "inicio", arraytable)
	} else {
		http.Error(writer, "401 Unauthorized", http.StatusUnauthorized)
		log.Println("Acceso no autorizado a la pagina Inicio")
	}
}
func Informacion(writer http.ResponseWriter, request *http.Request) {
	if RolClaim == "3" {
		idDato := request.URL.Query().Get("id")

		db := ConexionDB()
		defer func(db *sql.DB) {
			_ = db.Close()
		}(db)

		registros, err := db.Query("Select * From datos where id = $1", idDato)
		Err(err)
		arraytable2 = nil
		log.Println("Pagina de Informacion")
		for registros.Next() {
			err = registros.Scan(&ID, &FecAlta, &UserName, &CodigoZip, &CreditCardNum, &HashCreditCardNum, &CreditCardCcv, &HashCreditCardCcv, &CuentaNumero, &Direccion, &GeoLatitud, &GeoLongitud, &ColorFavorito, &FotoDni, &Ip, &Auto, &AutoModelo, &AutoTipo, &AutoColor, &CantidadComprasRealizadas, &Avatar, &FecBirthday)
			Err(err)
			table.ID = ID
			table.FecAlta = FecAlta
			table.UserName = UserName
			table.CodigoZip = CodigoZip
			table.HashCreditCardNum = HashCreditCardNum
			table.CreditCardCcv = CreditCardCcv
			table.HashCreditCardCcv = HashCreditCardCcv
			table.CuentaNumero = CuentaNumero
			table.Direccion = Direccion
			table.GeoLatitud = GeoLatitud
			table.GeoLongitud = GeoLongitud
			table.ColorFavorito = ColorFavorito
			table.FotoDni = FotoDni
			table.Ip = Ip
			table.Auto = Auto
			table.AutoModelo = AutoModelo
			table.AutoTipo = AutoTipo
			table.AutoColor = AutoColor
			table.CantidadComprasRealizadas = CantidadComprasRealizadas
			table.Avatar = Avatar
			table.FecBirthday = FecBirthday

			arraytable2 = append(arraytable2, table)

		}
		_ = tmpl.ExecuteTemplate(writer, "info", arraytable2)
	} else {
		http.Error(writer, "401 Unauthorized", http.StatusUnauthorized)
		log.Println("Acceso no autorizado a la pagina Información")
	}
}
func Json(writer http.ResponseWriter, request *http.Request) {
	idDatoUser := request.URL.Query().Get("username")
	idDatoToken := request.URL.Query().Get("token")
	log.Println("Obteniendo JSON")
	if idDatoToken == "" {
		log.Println("Sin Valor en la Variable Token")
		_, _ = fmt.Fprintf(writer, "%s", "nulo")

	} else {
		tokenDesarrollo, err := jwt.Parse(idDatoToken, func(token *jwt.Token) (interface{}, error) {
			log.Println("Verificando")
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("método de firma inválido: %v", token.Header["alg"])
				//goland:noinspection GoUnreachableCode,GoUnreachableCode
				log.Println("Metodo de firma invalido")
			}
			return jwtkey, nil
		})
		if err != nil {
			log.Println("Valor Invalido en la Variable Token")
			return
		}
		if tokenDesarrollo.Valid {
			claims, ok := tokenDesarrollo.Claims.(jwt.MapClaims)
			if !ok {
				log.Println("No se pudo obtener el claim de rol")
			}

			RolClaim, ok = claims["role"].(string)
			if !ok {
				log.Println("No se pudo obtener el claim de rol")
			}
			log.Printf("Rol: %s", RolClaim)
			if RolClaim == "2" || RolClaim == "1" {

				output := RemoverCaracteresEspeciales(idDatoUser)

				db := ConexionDB()
				defer func(db *sql.DB) {
					_ = db.Close()
				}(db)

				registros, err := db.Query("Select * From datos where username = $1", output)
				Err(err)
				defer func(registros *sql.Rows) {
					_ = registros.Close()
				}(registros)

				jsonview = nil

				for registros.Next() {
					err = registros.Scan(&ID, &FecAlta, &UserName, &CodigoZip, &CreditCardNum, &HashCreditCardNum, &CreditCardCcv, &HashCreditCardCcv, &CuentaNumero, &Direccion, &GeoLatitud, &GeoLongitud, &ColorFavorito, &FotoDni, &Ip, &Auto, &AutoModelo, &AutoTipo, &AutoColor, &CantidadComprasRealizadas, &Avatar, &FecBirthday)
					Err(err)
					jsonview = append(jsonview, Jsonview{FecAlta: FecAlta,
						UserName:                  UserName,
						HashcreditcardnumSha512:   HashCreditCardNum,
						HashcreditcardccvSha512:   HashCreditCardCcv,
						CuentaNumero:              CuentaNumero,
						GeoLatitud:                GeoLatitud,
						GeoLongitud:               GeoLongitud,
						Ip:                        Ip,
						CantidadComprasRealizadas: CantidadComprasRealizadas})

				}
				jsonData, err := json.Marshal(jsonview)
				Err(err)
				_, _ = fmt.Fprintf(writer, "%s", jsonData)
			}
		} else {
			http.Error(writer, "401 Unauthorized", http.StatusUnauthorized)
			log.Println("Acceso no autorizado a la pagina Inicio")
		}
	}

}
func Certificados() {
	currentDir, err := os.Getwd()
	Err(err)
	filePathKEY = filepath.Join(currentDir, "/certificados/server.key")
	filePathCERT = filepath.Join(currentDir, "/certificados/certbundle.pem")

}
func ObtenerIP(r *http.Request) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		return strings.Split(forwardedFor, ",")[0]
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return ip
}
func VerificarIPenWhiteList(ip string, whitelist []string) bool {
	whitelist = []string{
		"192.168.0.1",
		"10.0.0.1",
		"::1",
		"172.17.0.1",
	}
	for _, allowedIP := range whitelist {
		if ip == allowedIP {
			log.Printf("Acceso Permitido, %s en Whitelist", ip)
			return true
		}
	}
	log.Printf("Acceso Denegado, %s", ip)
	return false
}
