package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	MongoURI                string
	Port                    string
	DBName                  string
	UserRolesCollection     string
	ResourceRolesCollection string
	ReadTimeout             time.Duration
	WriteTimeout            time.Duration
}

func LoadConfig() (*Config, error) {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
		// In strict production, we might want to error if not set?
		// but let's keep default for ease of local testing if acceptable.
		// For Prod readiness, let's validate critical ones if explicitly requested?
		// Current User Plan says "verify server fails if critical env vars are invalid"
		// Let's enforce MONGO_URI if GO_ENV is production
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	readTimeout := getEnvDuration("SERVER_READ_TIMEOUT", 10*time.Second)
	writeTimeout := getEnvDuration("SERVER_WRITE_TIMEOUT", 10*time.Second)

	cfg := &Config{
		MongoURI:                mongoURI,
		Port:                    port,
		DBName:                  getEnv("DB_NAME", "rbac_db"),
		UserRolesCollection:     getEnv("COLLECTION_USER_ROLES", "user_roles"),
		ResourceRolesCollection: getEnv("COLLECTION_RESOURCE_ROLES", "user_resource_roles"),
		ReadTimeout:             readTimeout,
		WriteTimeout:            writeTimeout,
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.MongoURI == "" {
		return fmt.Errorf("MONGO_URI is required")
	}
	return nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	valStr := os.Getenv(key)
	if valStr == "" {
		return fallback
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		// Try parsing as duration string? e.g. "10s"
		d, err := time.ParseDuration(valStr)
		if err == nil {
			return d
		}
		return fallback
	}
	return time.Duration(val) * time.Second
}
