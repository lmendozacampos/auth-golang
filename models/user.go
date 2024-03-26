package models

// Definimos los parametros requeridos
type User struct {
	Id       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Phone    string `json:"string"`
}
