package server

import (
	"context"
	"errors"
	"log"
	"net/http"

	"example.com/auth/database"
	"example.com/auth/repository"
	"github.com/gorilla/mux"
)

// Configuración que nuestro servidor requiere para poder ejecutarse
// Tenemos las características del servidor
type Config struct {
	Port        string
	JWTSecret   string
	DatabaseUrl string
}

// Implementa el modelo de datos o estructura de config
type Server interface {
	Config() *Config
}

// Broker Encargado de manejar el typo server
// Nos ayuda a tener varias instancias de servidor corriendo
type Broker struct {
	config *Config
	router *mux.Router
}

// Hacer que el broker satisfaga el interface
func (b *Broker) Config() *Config {
	return b.config
}

// Constructor para servidor
// Busca problemas que se pueden encontrar
func NewServer(ctx context.Context, config *Config) (*Broker, error) {
	if config.Port == "" {
		return nil, errors.New("port is required")
	}
	if config.JWTSecret == "" {
		return nil, errors.New("jwt secret is required")
	}
	if config.DatabaseUrl == "" {
		return nil, errors.New("database url is required")
	}
	broker := &Broker{
		config: config,
		router: mux.NewRouter(),
	}
	return broker, nil
}

// Función que permite ejecutar el Broker
func (b *Broker) Start(binder func(s Server, r *mux.Router)) {
	b.router = mux.NewRouter()
	binder(b, b.router)
	repo, err := database.NewPostgresRepository(b.config.DatabaseUrl)
	if err != nil {
		log.Fatal(err)
	}
	repository.SetRepository(repo)
	log.Println("starting server on port", b.config.Port)
	if err := http.ListenAndServe(b.config.Port, b.router); err != nil {
		log.Println("error starting server:", err)
	} else {
		log.Fatalf("server stopped")
	}
}
