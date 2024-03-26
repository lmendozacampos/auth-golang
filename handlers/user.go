package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"example.com/auth/models"
	"example.com/auth/repository"
	"example.com/auth/server"
	"github.com/go-playground/validator"
	"github.com/golang-jwt/jwt"
	"github.com/segmentio/ksuid"
	"golang.org/x/crypto/bcrypt"
)

const HASH_COST = 8

var validate *validator.Validate

// Estructura de Respuesta
type SignUpResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

// Estructura de Registro
type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Phone    string `json:"phone"`
}

// Estructura de Inicio de sesión
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Estructura de Respuesta
type LoginResponse struct {
	Token string `json:"token"`
}

// Estructura de Respuesta
type BadResponse struct {
	Message string `json:"string"`
	Status  bool   `json:"status"`
}

// Handler que nos ayuda a hacer el registro del usuario
func SignUpHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var request = SignUpRequest{}
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res := validateSignUp(request, w)
		if res != 0 {
			return
		}

		res = securePassword(request, w)
		if res != 0 {
			return
		}

		// Validamos que el email no exista
		userEmail, _ := repository.GetUserByEmail(r.Context(), request.Email)
		if userEmail != nil && userEmail.Id != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(BadResponse{
				Message: "el correo ya se encuentra registrado",
				Status:  false,
			})
			return
		}
		// Validamos que el telefono no exista
		userPhone, _ := repository.GetUserByPhone(r.Context(), request.Phone)
		if userPhone != nil && userEmail.Id != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(BadResponse{
				Message: "el telefono ya se encuentra registrado",
				Status:  false,
			})
			return
		}

		// Crear id
		id, err := ksuid.NewRandom()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Cifrar contraseña
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), HASH_COST)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Guardar Datos
		var user = models.User{
			Email:    request.Email,
			Password: string(hashedPassword),
			Phone:    request.Phone,
			Id:       id.String(),
		}
		err = repository.InsertUser(r.Context(), &user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(SignUpResponse{
			ID:    user.Id,
			Email: user.Email,
			Phone: user.Phone,
		})

	}
}

// Handler para iniciar sesión
func LoginHandler(s server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request = LoginRequest{}
		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res := validateLogin(request, w)
		if res != 0 {
			return
		}

		// Validamos las credenciales
		user, err := repository.GetUserByEmail(r.Context(), request.Email)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(HomeResponse{
				Message: "Usuario incorrecto",
				Status:  false,
			})
			return
		}
		if user == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(HomeResponse{
				Message: "Usuario incorrecto",
				Status:  false,
			})
		}
		if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
			if user == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(HomeResponse{
					Message: "Contraseña incorrecta",
					Status:  false,
				})
			}
		}
		// Generamos token
		claims := models.AppClaims{
			UserId: user.Id,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(2 * time.Hour * 24).Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(s.Config().JWTSecret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Generamos respuesta
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(LoginResponse{
			Token: tokenString,
		})

	}
}

func validateSignUp(request SignUpRequest, w http.ResponseWriter) (response int) {
	validate = validator.New()

	// Validamos que se haya enviado el correo
	err := validate.Var(request.Email, "required")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "Falta el campo correo",
			Status:  false,
		})
		return 1
	}

	// Validamos que se haya enviado la contraseña
	err = validate.Var(request.Password, "required")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "Falta el campo contraseña",
			Status:  false,
		})
		return 1
	}

	// Validamos que se haya enviado el telefono
	err = validate.Var(request.Phone, "required")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "Falta el campo telefono",
			Status:  false,
		})
		return 1
	}

	// Validamos que sea formato correo
	err = validate.Var(request.Email, "email")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "El Formato del correo no es correcto",
			Status:  false,
		})
		return 1
	}

	// Validamos que sea formato el tamaño de la contraseña
	err = validate.Var(request.Password, "max=12,min=6")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "La contraseña debe contener entre 6 y 12 caracteres",
			Status:  false,
		})
		return 1
	}

	// Validamos que sea formato el tamaño del telefono
	err = validate.Var(request.Phone, "max=10,min=10")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "El telefono debe contener 10 digitos",
			Status:  false,
		})
		return 1
	}

	return 0
}

func validateLogin(request LoginRequest, w http.ResponseWriter) (response int) {
	validate = validator.New()

	// Validamos que se haya enviado el correo
	err := validate.Var(request.Email, "required")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "Falta el campo correo",
			Status:  false,
		})
		return 1
	}

	// Validamos que se haya enviado la contraseña
	err = validate.Var(request.Password, "required")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "Falta el campo contraseña",
			Status:  false,
		})
		return 1
	}

	return 0
}

func securePassword(request SignUpRequest, w http.ResponseWriter) (response int) {
	minusculaRegexp := regexp.MustCompile("[a-z]")
	numberRegexp := regexp.MustCompile("[0-9]")
	mayusculaRegexp := regexp.MustCompile("[A-Z]")
	especialRegexp := regexp.MustCompile("[^ a-zA-Z0-9]")

	firstValidation := minusculaRegexp.FindString(request.Password)
	secondValidation := numberRegexp.FindString(request.Password)
	thirdValidation := mayusculaRegexp.FindString(request.Password)
	fourthValidation := especialRegexp.FindString(request.Password)

	if firstValidation == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "La contraseña debe tener al menos una minúscula",
			Status:  false,
		})
		return 1
	}

	if secondValidation == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "La contraseña debe tener al menos un número",
			Status:  false,
		})
		return 1
	}

	if thirdValidation == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "La contraseña debe tener al menos una mayuscula",
			Status:  false,
		})
		return 1
	}

	if fourthValidation == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(HomeResponse{
			Message: "La contraseña debe tener al menos un caracter especial",
			Status:  false,
		})
		return 1
	}
	return 0
}
