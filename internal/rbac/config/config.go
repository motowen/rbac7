package config

import (
	"os"
)

type Config struct {
	MongoURI            string
	Port                string
	DBName              string
	UserRolesCollection string
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
		MongoURI:            mongoURI,
		Port:                port,
		DBName:              "rbac_db", // Could be env var too
		UserRolesCollection: getEnv("COLLECTION_USER_ROLES", "user_roles"),
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
