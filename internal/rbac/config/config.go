package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type JWTConfig struct {
	Issuer   string
	Audience string
	JWKSURL  string
}

type NATSConfig struct {
	URL string
}

type Config struct {
	MongoURI                string
	Port                    string
	DBName                  string
	UserRolesCollection     string
	ResourceRolesCollection string
	OrgUsersCollection      string
	ReadTimeout             time.Duration
	WriteTimeout            time.Duration
	JWT                     JWTConfig
	NATS                    NATSConfig
}

func LoadConfig() (*Config, error) {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
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
		OrgUsersCollection:      getEnv("COLLECTION_ORG_USERS", "org_users"),
		ReadTimeout:             readTimeout,
		WriteTimeout:            writeTimeout,
		JWT: JWTConfig{
			Issuer:   getEnv("JWT_ISSUER", ""),
			Audience: getEnv("JWT_AUDIENCE", ""),
			JWKSURL:  getEnv("JWT_JWKS_URL", ""),
		},
		NATS: NATSConfig{
			URL: getEnv("NATS_URL", ""),
		},
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
		d, err := time.ParseDuration(valStr)
		if err == nil {
			return d
		}
		return fallback
	}
	return time.Duration(val) * time.Second
}
