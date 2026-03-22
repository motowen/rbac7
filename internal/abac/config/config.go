package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds ABAC service configuration
type Config struct {
	MongoURI                   string
	Port                       string
	DBName                     string
	SubjectsCollection         string
	PolicyRulesCollection      string
	AttributeDefsCollection    string
	ReadTimeout                time.Duration
	WriteTimeout               time.Duration
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081" // Different from RBAC default 8080
	}

	readTimeout := getEnvDuration("SERVER_READ_TIMEOUT", 10*time.Second)
	writeTimeout := getEnvDuration("SERVER_WRITE_TIMEOUT", 10*time.Second)

	cfg := &Config{
		MongoURI:                mongoURI,
		Port:                    port,
		DBName:                  getEnv("DB_NAME", "abac_db"),
		SubjectsCollection:      getEnv("COLLECTION_SUBJECTS", "subjects"),
		PolicyRulesCollection:   getEnv("COLLECTION_POLICY_RULES", "policy_rules"),
		AttributeDefsCollection: getEnv("COLLECTION_ATTRIBUTE_DEFS", "attribute_definitions"),
		ReadTimeout:             readTimeout,
		WriteTimeout:            writeTimeout,
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate validates the config
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
