package config

import (
	"os"
)

type Config struct {
	MongoURI string
	Port     string
	DBName   string
}

func LoadConfig() *Config {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	return &Config{
		MongoURI: mongoURI,
		Port:     port,
		DBName:   "rbac_db", // Could be env var too
	}
}
