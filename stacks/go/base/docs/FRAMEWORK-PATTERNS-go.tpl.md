<!--
File: FRAMEWORK-PATTERNS-go.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Go Framework Patterns - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Go

## 🐹 Go Framework Patterns Overview

Go applications follow **standard library-first development** with **minimal external dependencies**, **concurrent architecture patterns**, and **microservices-oriented design**. This ensures performance, maintainability, and scalability across MVP, CORE, and FULL tiers while leveraging Go's strengths in backend services and CLI applications.

## 📊 Tier-Specific Framework Requirements

| Tier | Web Framework | Database | Testing | Deployment | Architecture |
|------|---------------|----------|---------|------------|--------------|
| **MVP** | Standard library | Basic SQL | Unit tests | Binary only | Simple CLI |
| **CORE** | Gin/Echo + gRPC | GORM/sqlx | Integration tests | Docker + Docker Compose | Microservices |
| **FULL** | Gin/Echo + gRPC + Service Mesh | Multi-database | All tests + benchmarks | Kubernetes + Helm | Distributed systems |

## 🔧 Go Module and Dependency Management

### **MVP Tier - Basic Module Structure**

```go
// go.mod - Simple module definition
module github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}

go 1.21

require (
    github.com/stretchr/testify v1.8.4
)
```

```go
// main.go - Single file CLI application
package main

import (
    "fmt"
    "log"
    "os"
    "strings"
)

type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: {{PROJECT_NAME_LOWER}} <command>")
        os.Exit(1)
    }

    command := os.Args[1]
    users := []User{
        {ID: 1, Name: "John Doe", Email: "john@example.com"},
        {ID: 2, Name: "Jane Smith", Email: "jane@example.com"},
    }

    switch strings.ToLower(command) {
    case "list":
        listUsers(users)
    case "count":
        fmt.Printf("Total users: %d\n", len(users))
    case "help":
        printHelp()
    default:
        fmt.Printf("Unknown command: %s\n", command)
        printHelp()
    }
}

func listUsers(users []User) {
    fmt.Println("Users:")
    for _, user := range users {
        fmt.Printf("  %d: %s (%s)\n", user.ID, user.Name, user.Email)
    }
}

func printHelp() {
    fmt.Println("Available commands:")
    fmt.Println("  list   - List all users")
    fmt.Println("  count  - Show total user count")
    fmt.Println("  help   - Show this help message")
}
```

### **CORE Tier - Production Module Structure**

```go
// go.mod - Production module with dependencies
module github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/spf13/cobra v1.7.0
    github.com/spf13/viper v1.16.0
    github.com/jmoiron/sqlx v1.3.5
    github.com/lib/pq v1.10.9
    github.com/golang-migrate/migrate/v4 v4.16.2
    github.com/stretchr/testify v1.8.4
    go.uber.org/zap v1.25.0
    github.com/swaggo/gin-swagger v1.6.0
    github.com/swaggo/files v1.0.1
    github.com/swaggo/swag v1.16.1
    google.golang.org/grpc v1.57.0
    google.golang.org/protobuf v1.31.0
    go.uber.org/dig v1.17.0
)

require (
    // Additional dependencies will be listed here
)
```

```go
// cmd/server/main.go - Production web server
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
    "go.uber.org/zap"

    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/config"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/database"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/handlers"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/middleware"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/repositories"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/services"
)

var rootCmd = &cobra.Command{
    Use:   "{{PROJECT_NAME_LOWER}}",
    Short: "{{PROJECT_NAME}} - Production Go application",
    Long:  "{{PROJECT_NAME}} is a production-ready Go application with web server and CLI capabilities",
}

var serverCmd = &cobra.Command{
    Use:   "server",
    Short: "Start the web server",
    Run:   runServer,
}

func init() {
    cobra.OnInitialize(initConfig)
    
    rootCmd.AddCommand(serverCmd)
    
    serverCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.{{PROJECT_NAME_LOWER}}.yaml)")
    serverCmd.PersistentFlags().String("host", "0.0.0.0", "server host")
    serverCmd.PersistentFlags().Int("port", 8080, "server port")
    serverCmd.PersistentFlags().Bool("debug", false, "enable debug mode")
    
    viper.BindPFlag("server.host", serverCmd.PersistentFlags().Lookup("host"))
    viper.BindPFlag("server.port", serverCmd.PersistentFlags().Lookup("port"))
    viper.BindPFlag("server.debug", serverCmd.PersistentFlags().Lookup("debug"))
}

var cfgFile string

func initConfig() {
    if cfgFile != "" {
        viper.SetConfigFile(cfgFile)
    } else {
        home, err := os.UserHomeDir()
        cobra.CheckErr(err)
        
        viper.AddConfigPath(home)
        viper.AddConfigPath(".")
        viper.SetConfigType("yaml")
        viper.SetConfigName(".{{PROJECT_NAME_LOWER}}")
    }
    
    viper.AutomaticEnv()
    
    if err := viper.ReadInConfig(); err == nil {
        log.Printf("Using config file: %s", viper.ConfigFileUsed())
    }
}

func runServer(cmd *cobra.Command, args []string) {
    logger, err := zap.NewProduction()
    if err != nil {
        log.Fatalf("Failed to initialize logger: %v", err)
    }
    defer logger.Sync()
    
    cfg := config.New()
    if err := cfg.Load(); err != nil {
        logger.Fatal("Failed to load config", zap.Error(err))
    }
    
    // Setup database
    db, err := database.New(cfg.Database)
    if err != nil {
        logger.Fatal("Failed to connect to database", zap.Error(err))
    }
    defer db.Close()
    
    // Setup dependencies
    container := dig.New()
    container.Provide(func() *zap.Logger { return logger })
    container.Provide(func() config.Config { return *cfg })
    container.Provide(func() *sqlx.DB { return db })
    
    // Setup repositories
    container.Provide(repositories.NewUserRepository)
    
    // Setup services
    container.Provide(services.NewUserService)
    
    // Setup handlers
    container.Provide(handlers.NewUserHandler)
    
    // Setup router
    if err := container.Invoke(func(userHandler *handlers.UserHandler) {
        router := setupRouter(cfg, userHandler, logger)
        
        server := &http.Server{
            Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
            Handler: router,
        }
        
        go func() {
            logger.Info("Starting server", 
                zap.String("host", cfg.Server.Host), 
                zap.Int("port", cfg.Server.Port))
            
            if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                logger.Fatal("Failed to start server", zap.Error(err))
            }
        }()
        
        // Graceful shutdown
        quit := make(chan os.Signal, 1)
        signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
        <-quit
        
        logger.Info("Shutting down server...")
        
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        
        if err := server.Shutdown(ctx); err != nil {
            logger.Fatal("Server forced to shutdown", zap.Error(err))
        }
        
        logger.Info("Server exited")
    }); err != nil {
        logger.Fatal("Failed to invoke dependencies", zap.Error(err))
    }
}

func setupRouter(cfg *config.Config, userHandler *handlers.UserHandler, logger *zap.Logger) *gin.Engine {
    if cfg.Server.Debug {
        gin.SetMode(gin.DebugMode)
    } else {
        gin.SetMode(gin.ReleaseMode)
    }
    
    router := gin.New()
    
    // Middleware
    router.Use(middleware.Logger(logger))
    router.Use(middleware.Recovery(logger))
    router.Use(middleware.CORS())
    router.Use(middleware.RequestID())
    
    // Health check
    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status":    "ok",
            "timestamp": time.Now().UTC(),
            "version":   "1.0.0",
        })
    })
    
    // API routes
    v1 := router.Group("/api/v1")
    {
        users := v1.Group("/users")
        {
            users.GET("", userHandler.GetUsers)
            users.GET("/:id", userHandler.GetUser)
            users.POST("", userHandler.CreateUser)
            users.PUT("/:id", userHandler.UpdateUser)
            users.DELETE("/:id", userHandler.DeleteUser)
        }
    }
    
    return router
}

func main() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

### **FULL Tier - Enterprise Module Structure**

```go
// go.mod - Enterprise module with comprehensive dependencies
module github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}

go 1.21

require (
    // Web Framework
    github.com/gin-gonic/gin v1.9.1
    github.com/swaggo/gin-swagger v1.6.0
    github.com/swaggo/files v1.0.1
    github.com/swaggo/swag v1.16.1
    
    // gRPC
    google.golang.org/grpc v1.57.0
    google.golang.org/protobuf v1.31.0
    github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.0
    
    // CLI
    github.com/spf13/cobra v1.7.0
    github.com/spf13/viper v1.16.0
    
    // Database
    github.com/jmoiron/sqlx v1.3.5
    github.com/lib/pq v1.10.9
    github.com/go-redis/redis/v8 v8.11.5
    github.com/golang-migrate/migrate/v4 v4.16.2
    
    // ORM/Query Builder
    github.com/gedex/inflector v1.0.0
    github.com/Masterminds/squirrel v1.5.4
    
    // Dependency Injection
    go.uber.org/dig v1.17.0
    
    // Logging
    go.uber.org/zap v1.25.0
    github.com/lmittmann/tint v1.0.0
    
    // Configuration
    github.com/knadh/koanf v1.5.0
    github.com/knadh/koanf/providers/file v1.0.0
    github.com/knadh/koanf/parsers/yaml v1.0.0
    
    // Validation
    github.com/go-playground/validator/v10 v10.15.1
    
    // Authentication
    github.com/golang-jwt/jwt/v5 v5.0.0
    golang.org/x/crypto v0.13.0
    
    // Monitoring
    github.com/prometheus/client_golang v1.16.0
    go.opentelemetry.io/otel v1.19.0
    go.opentelemetry.io/otel/exporters/jaeger v1.17.0
    go.opentelemetry.io/otel/sdk v1.19.0
    go.opentelemetry.io/otel/trace v1.19.0
    
    // Messaging
    github.com/segmentio/kafka-go v0.4.47
    github.com/streadway/amqp v1.1.0
    
    // Caching
    github.com/allegro/bigcache/v3 v3.1.0
    
    // Rate Limiting
    github.com/ulule/limiter/v3 v3.11.1
    
    // Testing
    github.com/stretchr/testify v1.8.4
    github.com/golang/mock v1.6.0
    github.com/testcontainers/testcontainers-go v0.25.0
    
    // Utilities
    github.com/google/uuid v1.3.0
    github.com/pkg/errors v0.9.1
)
```

```go
// cmd/server/main.go - Enterprise microservice
package main

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/jaeger"
    "go.opentelemetry.io/otel/sdk/resource"
    "go.opentelemetry.io/otel/sdk/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
    "go.uber.org/zap"
    "google.golang.org/grpc"
    "google.golang.org/grpc/reflection"

    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/config"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/database"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/grpc/handlers"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/grpc/interceptors"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/http/handlers"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/http/middleware"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/messaging"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/monitoring"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/repositories"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/services"
    pb "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/proto/gen/go"
)

var rootCmd = &cobra.Command{
    Use:   "{{PROJECT_NAME_LOWER}}",
    Short: "{{PROJECT_NAME}} - Enterprise Go microservice",
    Long:  "{{PROJECT_NAME}} is an enterprise-grade Go microservice with HTTP, gRPC, and messaging capabilities",
}

var serverCmd = &cobra.Command{
    Use:   "server",
    Short: "Start the microservice",
    Run:   runServer,
}

func init() {
    cobra.OnInitialize(initConfig)
    
    rootCmd.AddCommand(serverCmd)
    
    serverCmd.PersistentFlags().String("config", "", "config file path")
    serverCmd.PersistentFlags().String("host", "0.0.0.0", "HTTP server host")
    serverCmd.PersistentFlags().Int("http-port", 8080, "HTTP server port")
    serverCmd.PersistentFlags().Int("grpc-port", 9090, "gRPC server port")
    serverCmd.PersistentFlags().Bool("debug", false, "enable debug mode")
    serverCmd.PersistentFlags().Bool("enable-metrics", true, "enable Prometheus metrics")
    serverCmd.PersistentFlags().Bool("enable-tracing", true, "enable OpenTelemetry tracing")
    
    viper.BindPFlag("server.host", serverCmd.PersistentFlags().Lookup("host"))
    viper.BindPFlag("server.http_port", serverCmd.PersistentFlags().Lookup("http-port"))
    viper.BindPFlag("server.grpc_port", serverCmd.PersistentFlags().Lookup("grpc-port"))
    viper.BindPFlag("server.debug", serverCmd.PersistentFlags().Lookup("debug"))
    viper.BindPFlag("monitoring.metrics.enabled", serverCmd.PersistentFlags().Lookup("enable-metrics"))
    viper.BindPFlag("monitoring.tracing.enabled", serverCmd.PersistentFlags().Lookup("enable-tracing"))
}

func initConfig() {
    if configFile := viper.GetString("config"); configFile != "" {
        viper.SetConfigFile(configFile)
    } else {
        viper.SetConfigName("config")
        viper.SetConfigType("yaml")
        viper.AddConfigPath(".")
        viper.AddConfigPath("./config")
        viper.AddConfigPath("/etc/{{PROJECT_NAME_LOWER}}")
    }
    
    viper.AutomaticEnv()
    viper.SetEnvPrefix("{{PROJECT_NAME_UPPER}}")
    
    if err := viper.ReadInConfig(); err == nil {
        fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
    }
}

func runServer(cmd *cobra.Command, args []string) {
    logger := setupLogger()
    defer logger.Sync()
    
    cfg := config.New()
    if err := cfg.Load(); err != nil {
        logger.Fatal("Failed to load config", zap.Error(err))
    }
    
    // Setup monitoring
    if cfg.Monitoring.Tracing.Enabled {
        setupTracing(cfg, logger)
    }
    
    // Setup database connections
    primaryDB, err := database.New(cfg.Database.Primary)
    if err != nil {
        logger.Fatal("Failed to connect to primary database", zap.Error(err))
    }
    defer primaryDB.Close()
    
    var readDB *sqlx.DB
    if cfg.Database.Read != nil {
        readDB, err = database.New(cfg.Database.Read)
        if err != nil {
            logger.Fatal("Failed to connect to read database", zap.Error(err))
        }
        defer readDB.Close()
    }
    
    // Setup Redis
    redisClient, err := database.NewRedis(cfg.Redis)
    if err != nil {
        logger.Fatal("Failed to connect to Redis", zap.Error(err))
    }
    defer redisClient.Close()
    
    // Setup messaging
    kafkaProducer, err := messaging.NewKafkaProducer(cfg.Kafka)
    if err != nil {
        logger.Fatal("Failed to setup Kafka producer", zap.Error(err))
    }
    defer kafkaProducer.Close()
    
    // Setup dependency injection container
    container := setupContainer(logger, cfg, primaryDB, readDB, redisClient, kafkaProducer)
    
    // Start HTTP server
    httpServer := startHTTPServer(cfg, container, logger)
    
    // Start gRPC server
    grpcServer := startGRPCServer(cfg, container, logger)
    
    // Setup graceful shutdown
    setupGracefulShutdown(logger, httpServer, grpcServer)
}

func setupLogger() *zap.Logger {
    if viper.GetBool("server.debug") {
        logger, err := zap.NewDevelopment()
        if err != nil {
            log.Fatalf("Failed to initialize logger: %v", err)
        }
        return logger
    }
    
    logger, err := zap.NewProduction()
    if err != nil {
        log.Fatalf("Failed to initialize logger: %v", err)
    }
    return logger
}

func setupTracing(cfg *config.Config, logger *zap.Logger) {
    exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(
        jaeger.WithEndpoint(cfg.Monitoring.Tracing.JaegerEndpoint),
    ))
    if err != nil {
        logger.Fatal("Failed to create Jaeger exporter", zap.Error(err))
    }
    
    tp := trace.NewTracerProvider(
        trace.WithBatcher(exporter),
        trace.WithResource(resource.NewWithAttributes(
            semconv.SchemaURL,
            semconv.ServiceNameKey.String("{{PROJECT_NAME_LOWER}}"),
            semconv.ServiceVersionKey.String(cfg.Version),
        )),
    )
    
    otel.SetTracerProvider(tp)
    
    logger.Info("Tracing initialized", zap.String("jaeger_endpoint", cfg.Monitoring.Tracing.JaegerEndpoint))
}

func setupContainer(logger *zap.Logger, cfg *config.Config, primaryDB, readDB *sqlx.DB, redisClient *redis.Client, kafkaProducer *kafka.Writer) *dig.Container {
    container := dig.New()
    
    // Core dependencies
    container.Provide(func() *zap.Logger { return logger })
    container.Provide(func() config.Config { return *cfg })
    container.Provide(func() *sqlx.DB { return primaryDB })
    container.Provide(func() *sqlx.DB { return readDB })
    container.Provide(func() *redis.Client { return redisClient })
    container.Provide(func() *kafka.Writer { return kafkaProducer })
    
    // Repositories
    container.Provide(repositories.NewUserRepository)
    container.Provide(repositories.NewProductRepository)
    
    // Services
    container.Provide(services.NewUserService)
    container.Provide(services.NewProductService)
    container.Provide(services.NewAuthService)
    
    // HTTP handlers
    container.Provide(handlers.NewUserHandler)
    container.Provide(handlers.NewProductHandler)
    container.Provide(handlers.NewAuthHandler)
    
    // gRPC handlers
    container.Provide(handlers.NewUserGRPCHandler)
    container.Provide(handlers.NewProductGRPCHandler)
    
    return container
}

func startHTTPServer(cfg *config.Config, container *dig.Container, logger *zap.Logger) *http.Server {
    var router *gin.Engine
    
    if err := container.Invoke(func(
        userHandler *handlers.UserHandler,
        productHandler *handlers.ProductHandler,
        authHandler *handlers.AuthHandler,
    ) {
        router = setupHTTPRouter(cfg, userHandler, productHandler, authHandler, logger)
    }); err != nil {
        logger.Fatal("Failed to setup HTTP router", zap.Error(err))
    }
    
    server := &http.Server{
        Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.HTTPPort),
        Handler: router,
    }
    
    go func() {
        logger.Info("Starting HTTP server", 
            zap.String("host", cfg.Server.Host), 
            zap.Int("port", cfg.Server.HTTPPort))
        
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            logger.Fatal("Failed to start HTTP server", zap.Error(err))
        }
    }()
    
    return server
}

func startGRPCServer(cfg *config.Config, container *dig.Container, logger *zap.Logger) *grpc.Server {
    var grpcHandler *handlers.UserGRPCServer
    
    if err := container.Invoke(func(handler *handlers.UserGRPCServer) {
        grpcHandler = handler
    }); err != nil {
        logger.Fatal("Failed to setup gRPC handler", zap.Error(err))
    }
    
    lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.GRPCPort))
    if err != nil {
        logger.Fatal("Failed to listen for gRPC", zap.Error(err))
    }
    
    s := grpc.NewServer(
        grpc.UnaryInterceptor(interceptors.LoggingInterceptor(logger)),
        grpc.UnaryInterceptor(interceptors.TracingInterceptor()),
        grpc.UnaryInterceptor(interceptors.MetricsInterceptor()),
    )
    
    pb.RegisterUserServiceServer(s, grpcHandler)
    reflection.Register(s)
    
    go func() {
        logger.Info("Starting gRPC server", 
            zap.String("host", cfg.Server.Host), 
            zap.Int("port", cfg.Server.GRPCPort))
        
        if err := s.Serve(lis); err != nil {
            logger.Fatal("Failed to start gRPC server", zap.Error(err))
        }
    }()
    
    return s
}

func setupHTTPRouter(cfg *config.Config, 
    userHandler *handlers.UserHandler,
    productHandler *handlers.ProductHandler,
    authHandler *handlers.AuthHandler,
    logger *zap.Logger) *gin.Engine {
    
    if cfg.Server.Debug {
        gin.SetMode(gin.DebugMode)
    } else {
        gin.SetMode(gin.ReleaseMode)
    }
    
    router := gin.New()
    
    // Middleware
    router.Use(middleware.Logger(logger))
    router.Use(middleware.Recovery(logger))
    router.Use(middleware.CORS())
    router.Use(middleware.RequestID())
    router.Use(middleware.Tracing())
    router.Use(middleware.Metrics())
    
    // Health check
    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status":    "ok",
            "timestamp": time.Now().UTC(),
            "version":   cfg.Version,
            "service":   "{{PROJECT_NAME_LOWER}}",
        })
    })
    
    // Metrics endpoint
    if cfg.Monitoring.Metrics.Enabled {
        router.GET("/metrics", gin.WrapH(promhttp.Handler()))
    }
    
    // API v1 routes
    v1 := router.Group("/api/v1")
    {
        // Public routes
        auth := v1.Group("/auth")
        {
            auth.POST("/login", authHandler.Login)
            auth.POST("/register", authHandler.Register)
            auth.POST("/refresh", authHandler.RefreshToken)
        }
        
        // Protected routes
        protected := v1.Group("")
        protected.Use(middleware.Auth(cfg.JWT.Secret))
        {
            users := protected.Group("/users")
            {
                users.GET("", userHandler.GetUsers)
                users.GET("/:id", userHandler.GetUser)
                users.POST("", userHandler.CreateUser)
                users.PUT("/:id", userHandler.UpdateUser)
                users.DELETE("/:id", userHandler.DeleteUser)
            }
            
            products := protected.Group("/products")
            {
                products.GET("", productHandler.GetProducts)
                products.GET("/:id", productHandler.GetProduct)
                products.POST("", productHandler.CreateProduct)
                products.PUT("/:id", productHandler.UpdateProduct)
                products.DELETE("/:id", productHandler.DeleteProduct)
            }
        }
    }
    
    return router
}

func setupGracefulShutdown(logger *zap.Logger, httpServer *http.Server, grpcServer *grpc.Server) {
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    logger.Info("Shutting down servers...")
    
    // Shutdown HTTP server
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := httpServer.Shutdown(ctx); err != nil {
        logger.Error("HTTP server forced to shutdown", zap.Error(err))
    }
    
    // Shutdown gRPC server
    grpcServer.GracefulStop()
    
    logger.Info("Servers exited")
}

func main() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

## 🌐 Web Framework Patterns

### **MVP Tier - Standard Library HTTP**

```go
// internal/server/server.go - Simple HTTP server
package server

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strconv"
    "sync"
    "time"
)

type User struct {
    ID        int       `json:"id"`
    Name      string    `json:"name"`
    Email     string    `json:"email"`
    CreatedAt time.Time `json:"created_at"`
}

type Server struct {
    users  []User
    mu     sync.RWMutex
    nextID int
}

func NewServer() *Server {
    return &Server{
        users: []User{
            {ID: 1, Name: "John Doe", Email: "john@example.com", CreatedAt: time.Now()},
            {ID: 2, Name: "Jane Smith", Email: "jane@example.com", CreatedAt: time.Now()},
        },
        nextID: 3,
    }
}

func (s *Server) Start(port int) error {
    mux := http.NewServeMux()
    
    // Routes
    mux.HandleFunc("/", s.handleHome)
    mux.HandleFunc("/health", s.handleHealth)
    mux.HandleFunc("/api/users", s.handleUsers)
    mux.HandleFunc("/api/users/", s.handleUser)
    
    server := &http.Server{
        Addr:         fmt.Sprintf(":%d", port),
        Handler:      mux,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    
    log.Printf("Server starting on port %d", port)
    return server.ListenAndServe()
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "service": "{{PROJECT_NAME_LOWER}}",
        "version": "1.0.0",
    })
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status":    "ok",
        "timestamp": time.Now().UTC(),
    })
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    switch r.Method {
    case http.MethodGet:
        s.getUsers(w, r)
    case http.MethodPost:
        s.createUser(w, r)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
    idStr := r.URL.Path[len("/api/users/"):]
    id, err := strconv.Atoi(idStr)
    if err != nil {
        http.Error(w, "Invalid user ID", http.StatusBadRequest)
        return
    }
    
    switch r.Method {
    case http.MethodGet:
        s.getUser(w, r, id)
    case http.MethodPut:
        s.updateUser(w, r, id)
    case http.MethodDelete:
        s.deleteUser(w, r, id)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func (s *Server) getUsers(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(s.users)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    s.mu.Lock()
    defer s.mu.Unlock()
    
    user.ID = s.nextID
    user.CreatedAt = time.Now()
    s.users = append(s.users, user)
    s.nextID++
    
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(user)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, id int) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    for _, user := range s.users {
        if user.ID == id {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(user)
            return
        }
    }
    
    http.Error(w, "User not found", http.StatusNotFound)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, id int) {
    var updatedUser User
    if err := json.NewDecoder(r.Body).Decode(&updatedUser); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    s.mu.Lock()
    defer s.mu.Unlock()
    
    for i, user := range s.users {
        if user.ID == id {
            updatedUser.ID = id
            updatedUser.CreatedAt = user.CreatedAt
            s.users[i] = updatedUser
            
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(updatedUser)
            return
        }
    }
    
    http.Error(w, "User not found", http.StatusNotFound)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, id int) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    for i, user := range s.users {
        if user.ID == id {
            s.users = append(s.users[:i], s.users[i+1:]...)
            w.WriteHeader(http.StatusNoContent)
            return
        }
    }
    
    http.Error(w, "User not found", http.StatusNotFound)
}
```

### **CORE Tier - Gin Web Framework**

```go
// internal/handlers/user_handler.go - Production user handler
package handlers

import (
    "net/http"
    "strconv"
    
    "github.com/gin-gonic/gin"
    "github.com/go-playground/validator/v10"
    "go.uber.org/zap"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/dto"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/services"
)

type UserHandler struct {
    userService services.UserService
    validator   *validator.Validate
    logger      *zap.Logger
}

func NewUserHandler(userService services.UserService, logger *zap.Logger) *UserHandler {
    return &UserHandler{
        userService: userService,
        validator:   validator.New(),
        logger:      logger,
    }
}

// GetUsers godoc
// @Summary Get all users
// @Description Get all users with pagination
// @Tags users
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} dto.PaginatedUsersResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users [get]
func (h *UserHandler) GetUsers(c *gin.Context) {
    page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
    limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
    
    if page < 1 {
        page = 1
    }
    if limit < 1 || limit > 100 {
        limit = 10
    }
    
    users, total, err := h.userService.GetUsers(c.Request.Context(), page, limit)
    if err != nil {
        h.logger.Error("Failed to get users", zap.Error(err))
        c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
            Error:   "internal_server_error",
            Message: "Failed to get users",
        })
        return
    }
    
    c.JSON(http.StatusOK, dto.PaginatedUsersResponse{
        Users: users,
        Pagination: dto.Pagination{
            Page:  page,
            Limit: limit,
            Total: total,
        },
    })
}

// GetUser godoc
// @Summary Get user by ID
// @Description Get a specific user by ID
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} dto.UserResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users/{id} [get]
func (h *UserHandler) GetUser(c *gin.Context) {
    id, err := strconv.ParseUint(c.Param("id"), 10, 32)
    if err != nil {
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_user_id",
            Message: "Invalid user ID format",
        })
        return
    }
    
    user, err := h.userService.GetUserByID(c.Request.Context(), uint(id))
    if err != nil {
        if err == services.ErrUserNotFound {
            c.JSON(http.StatusNotFound, dto.ErrorResponse{
                Error:   "user_not_found",
                Message: "User not found",
            })
            return
        }
        
        h.logger.Error("Failed to get user", zap.Uint("id", uint(id)), zap.Error(err))
        c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
            Error:   "internal_server_error",
            Message: "Failed to get user",
        })
        return
    }
    
    c.JSON(http.StatusOK, dto.UserResponse{User: user})
}

// CreateUser godoc
// @Summary Create new user
// @Description Create a new user
// @Tags users
// @Accept json
// @Produce json
// @Param user body dto.CreateUserRequest true "User data"
// @Success 201 {object} dto.UserResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users [post]
func (h *UserHandler) CreateUser(c *gin.Context) {
    var req dto.CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_request",
            Message: err.Error(),
        })
        return
    }
    
    if err := h.validator.Struct(&req); err != nil {
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "validation_error",
            Message: err.Error(),
        })
        return
    }
    
    user, err := h.userService.CreateUser(c.Request.Context(), &req)
    if err != nil {
        if err == services.ErrUserAlreadyExists {
            c.JSON(http.StatusConflict, dto.ErrorResponse{
                Error:   "user_already_exists",
                Message: "User with this email already exists",
            })
            return
        }
        
        h.logger.Error("Failed to create user", zap.Error(err))
        c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
            Error:   "internal_server_error",
            Message: "Failed to create user",
        })
        return
    }
    
    c.JSON(http.StatusCreated, dto.UserResponse{User: user})
}

// UpdateUser godoc
// @Summary Update user
// @Description Update an existing user
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param user body dto.UpdateUserRequest true "User data"
// @Success 200 {object} dto.UserResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users/{id} [put]
func (h *UserHandler) UpdateUser(c *gin.Context) {
    id, err := strconv.ParseUint(c.Param("id"), 10, 32)
    if err != nil {
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_user_id",
            Message: "Invalid user ID format",
        })
        return
    }
    
    var req dto.UpdateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_request",
            Message: err.Error(),
        })
        return
    }
    
    if err := h.validator.Struct(&req); err != nil {
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "validation_error",
            Message: err.Error(),
        })
        return
    }
    
    user, err := h.userService.UpdateUser(c.Request.Context(), uint(id), &req)
    if err != nil {
        if err == services.ErrUserNotFound {
            c.JSON(http.StatusNotFound, dto.ErrorResponse{
                Error:   "user_not_found",
                Message: "User not found",
            })
            return
        }
        
        h.logger.Error("Failed to update user", zap.Uint("id", uint(id)), zap.Error(err))
        c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
            Error:   "internal_server_error",
            Message: "Failed to update user",
        })
        return
    }
    
    c.JSON(http.StatusOK, dto.UserResponse{User: user})
}

// DeleteUser godoc
// @Summary Delete user
// @Description Delete an existing user
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 204
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users/{id} [delete]
func (h *UserHandler) DeleteUser(c *gin.Context) {
    id, err := strconv.ParseUint(c.Param("id"), 10, 32)
    if err != nil {
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_user_id",
            Message: "Invalid user ID format",
        })
        return
    }
    
    err = h.userService.DeleteUser(c.Request.Context(), uint(id))
    if err != nil {
        if err == services.ErrUserNotFound {
            c.JSON(http.StatusNotFound, dto.ErrorResponse{
                Error:   "user_not_found",
                Message: "User not found",
            })
            return
        }
        
        h.logger.Error("Failed to delete user", zap.Uint("id", uint(id)), zap.Error(err))
        c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
            Error:   "internal_server_error",
            Message: "Failed to delete user",
        })
        return
    }
    
    c.Status(http.StatusNoContent)
}
```

### **FULL Tier - Advanced Gin with Middleware**

```go
// internal/handlers/enterprise_user_handler.go - Enterprise user handler
package handlers

import (
    "net/http"
    "strconv"
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/go-playground/validator/v10"
    "go.opentelemetry.io/otel/trace"
    "go.uber.org/zap"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/dto"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/services"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/middleware"
)

type EnterpriseUserHandler struct {
    userService services.UserService
    validator   *validator.Validate
    logger      *zap.Logger
    cache       CacheService
    metrics     MetricsService
}

func NewEnterpriseUserHandler(
    userService services.UserService,
    logger *zap.Logger,
    cache CacheService,
    metrics MetricsService,
) *EnterpriseUserHandler {
    return &EnterpriseUserHandler{
        userService: userService,
        validator:   validator.New(),
        logger:      logger,
        cache:       cache,
        metrics:     metrics,
    }
}

// GetUsers godoc
// @Summary Get all users with advanced filtering
// @Description Get all users with pagination, filtering, and sorting
// @Tags users
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search term"
// @Param sort query string false "Sort field" default("created_at")
// @Param order query string false "Sort order" default("desc")
// @Param status query string false "User status filter"
// @Param role query string false "User role filter"
// @Success 200 {object} dto.PaginatedUsersResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users [get]
func (h *UserHandler) GetUsers(c *gin.Context) {
    span := trace.SpanFromContext(c.Request.Context())
    span.SetAttributes(
        attribute.String("handler", "GetUsers"),
    )
    
    start := time.Now()
    defer func() {
        h.metrics.RecordDuration("users.get_all", time.Since(start))
    }()
    
    // Parse and validate query parameters
    req, err := h.parseUserListRequest(c)
    if err != nil {
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_request",
            Message: err.Error(),
        })
        return
    }
    
    // Try cache first
    cacheKey := h.generateUserListCacheKey(req)
    if cached, err := h.cache.Get(c.Request.Context(), cacheKey); err == nil {
        h.metrics.IncrementCounter("users.cache_hit")
        c.JSON(http.StatusOK, cached)
        return
    }
    
    users, total, err := h.userService.GetUsersWithFilters(c.Request.Context(), req)
    if err != nil {
        h.logger.Error("Failed to get users", zap.Error(err))
        h.metrics.IncrementCounter("users.get_all.error")
        c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
            Error:   "internal_server_error",
            Message: "Failed to get users",
        })
        return
    }
    
    response := dto.PaginatedUsersResponse{
        Users: users,
        Pagination: dto.Pagination{
            Page:  req.Page,
            Limit: req.Limit,
            Total: total,
        },
    }
    
    // Cache response for 5 minutes
    h.cache.Set(c.Request.Context(), cacheKey, response, 5*time.Minute)
    h.metrics.IncrementCounter("users.cache_miss")
    
    c.JSON(http.StatusOK, response)
}

// GetUser godoc
// @Summary Get user by ID with detailed information
// @Description Get a specific user by ID with full details and analytics
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param include query string false "Include additional data" Enums("analytics,permissions,groups")
// @Success 200 {object} dto.DetailedUserResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users/{id} [get]
func (h *UserHandler) GetUser(c *gin.Context) {
    span := trace.SpanFromContext(c.Request.Context())
    span.SetAttributes(
        attribute.String("handler", "GetUser"),
    )
    
    start := time.Now()
    defer func() {
        h.metrics.RecordDuration("users.get_by_id", time.Since(start))
    }()
    
    id, err := strconv.ParseUint(c.Param("id"), 10, 32)
    if err != nil {
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_user_id",
            Message: "Invalid user ID format",
        })
        return
    }
    
    include := c.Query("include")
    
    // Try cache first
    cacheKey := fmt.Sprintf("user:%d:include:%s", id, include)
    if cached, err := h.cache.Get(c.Request.Context(), cacheKey); err == nil {
        h.metrics.IncrementCounter("users.cache_hit")
        c.JSON(http.StatusOK, cached)
        return
    }
    
    user, err := h.userService.GetUserByIDWithDetails(c.Request.Context(), uint(id), include)
    if err != nil {
        if err == services.ErrUserNotFound {
            h.metrics.IncrementCounter("users.get_by_id.not_found")
            c.JSON(http.StatusNotFound, dto.ErrorResponse{
                Error:   "user_not_found",
                Message: "User not found",
            })
            return
        }
        
        h.logger.Error("Failed to get user", zap.Uint("id", uint(id)), zap.Error(err))
        h.metrics.IncrementCounter("users.get_by_id.error")
        c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
            Error:   "internal_server_error",
            Message: "Failed to get user",
        })
        return
    }
    
    response := dto.DetailedUserResponse{User: user}
    
    // Cache response for 10 minutes
    h.cache.Set(c.Request.Context(), cacheKey, response, 10*time.Minute)
    h.metrics.IncrementCounter("users.cache_miss")
    
    c.JSON(http.StatusOK, response)
}

// CreateUser godoc
// @Summary Create new user with validation and analytics
// @Description Create a new user with comprehensive validation and analytics tracking
// @Tags users
// @Accept json
// @Produce json
// @Param user body dto.CreateUserRequest true "User data"
// @Success 201 {object} dto.UserResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users [post]
func (h *UserHandler) CreateUser(c *gin.Context) {
    span := trace.SpanFromContext(c.Request.Context())
    span.SetAttributes(
        attribute.String("handler", "CreateUser"),
    )
    
    start := time.Now()
    defer func() {
        h.metrics.RecordDuration("users.create", time.Since(start))
    }()
    
    var req dto.CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        h.metrics.IncrementCounter("users.create.validation_error")
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_request",
            Message: err.Error(),
        })
        return
    }
    
    // Comprehensive validation
    if err := h.validator.Struct(&req); err != nil {
        h.metrics.IncrementCounter("users.create.validation_error")
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "validation_error",
            Message: err.Error(),
        })
        return
    }
    
    // Additional business validation
    if err := h.validateBusinessRules(&req); err != nil {
        h.metrics.IncrementCounter("users.create.business_validation_error")
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "business_validation_error",
            Message: err.Error(),
        })
        return
    }
    
    user, err := h.userService.CreateUserWithAnalytics(c.Request.Context(), &req)
    if err != nil {
        if err == services.ErrUserAlreadyExists {
            h.metrics.IncrementCounter("users.create.already_exists")
            c.JSON(http.StatusConflict, dto.ErrorResponse{
                Error:   "user_already_exists",
                Message: "User with this email already exists",
            })
            return
        }
        
        h.logger.Error("Failed to create user", zap.Error(err))
        h.metrics.IncrementCounter("users.create.error")
        c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
            Error:   "internal_server_error",
            Message: "Failed to create user",
        })
        return
    }
    
    h.metrics.IncrementCounter("users.create.success")
    
    // Invalidate relevant cache
    h.cache.InvalidatePattern(c.Request.Context(), "users:list:*")
    
    c.JSON(http.StatusCreated, dto.UserResponse{User: user})
}

// BulkCreateUsers godoc
// @Summary Create multiple users
// @Description Create multiple users in a single transaction
// @Tags users
// @Accept json
// @Produce json
// @Param users body dto.BulkCreateUsersRequest true "Users data"
// @Success 201 {object} dto.BulkUsersResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users/bulk [post]
func (h *UserHandler) BulkCreateUsers(c *gin.Context) {
    span := trace.SpanFromContext(c.Request.Context())
    span.SetAttributes(
        attribute.String("handler", "BulkCreateUsers"),
    )
    
    start := time.Now()
    defer func() {
        h.metrics.RecordDuration("users.bulk_create", time.Since(start))
    }()
    
    var req dto.BulkCreateUsersRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        h.metrics.IncrementCounter("users.bulk_create.validation_error")
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_request",
            Message: err.Error(),
        })
        return
    }
    
    if len(req.Users) == 0 || len(req.Users) > 100 {
        h.metrics.IncrementCounter("users.bulk_create.validation_error")
        c.JSON(http.StatusBadRequest, dto.ErrorResponse{
            Error:   "invalid_bulk_size",
            Message: "Bulk size must be between 1 and 100",
        })
        return
    }
    
    // Validate all users
    for _, user := range req.Users {
        if err := h.validator.Struct(&user); err != nil {
            h.metrics.IncrementCounter("users.bulk_create.validation_error")
            c.JSON(http.StatusBadRequest, dto.ErrorResponse{
                Error:   "validation_error",
                Message: err.Error(),
            })
            return
        }
    }
    
    result, err := h.userService.BulkCreateUsers(c.Request.Context(), req.Users)
    if err != nil {
        h.logger.Error("Failed to bulk create users", zap.Error(err))
        h.metrics.IncrementCounter("users.bulk_create.error")
        c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
            Error:   "internal_server_error",
            Message: "Failed to create users",
        })
        return
    }
    
    h.metrics.IncrementCounter("users.bulk_create.success", map[string]string{
        "created_count": strconv.Itoa(len(result.Created)),
        "failed_count":  strconv.Itoa(len(result.Failed)),
    })
    
    // Invalidate cache
    h.cache.InvalidatePattern(c.Request.Context(), "users:list:*")
    
    c.JSON(http.StatusCreated, result)
}

// Helper methods
func (h *UserHandler) parseUserListRequest(c *gin.Context) (*dto.UserListRequest, error) {
    page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
    limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
    search := c.Query("search")
    sort := c.DefaultQuery("sort", "created_at")
    order := c.DefaultQuery("order", "desc")
    status := c.Query("status")
    role := c.Query("role")
    
    if page < 1 {
        page = 1
    }
    if limit < 1 || limit > 100 {
        limit = 10
    }
    
    if order != "asc" && order != "desc" {
        order = "desc"
    }
    
    return &dto.UserListRequest{
        Page:   page,
        Limit:  limit,
        Search: search,
        Sort:   sort,
        Order:  order,
        Status: status,
        Role:   role,
    }, nil
}

func (h *UserHandler) validateBusinessRules(req *dto.CreateUserRequest) error {
    // Check email domain restrictions
    if h.isRestrictedEmailDomain(req.Email) {
        return errors.New("email domain is not allowed")
    }
    
    // Check password strength
    if !h.isStrongPassword(req.Password) {
        return errors.New("password does not meet security requirements")
    }
    
    return nil
}

func (h *UserHandler) generateUserListCacheKey(req *dto.UserListRequest) string {
    return fmt.Sprintf("users:list:%d:%d:%s:%s:%s:%s:%s",
        req.Page, req.Limit, req.Search, req.Sort, req.Order, req.Status, req.Role)
}

func (h *UserHandler) isRestrictedEmailDomain(email string) bool {
    restrictedDomains := []string{"tempmail.com", "throwaway.email"}
    domain := strings.Split(email, "@")[1]
    
    for _, restricted := range restrictedDomains {
        if domain == restricted {
            return true
        }
    }
    return false
}

func (h *UserHandler) isStrongPassword(password string) bool {
    if len(password) < 8 {
        return false
    }
    
    hasUpper := false
    hasLower := false
    hasNumber := false
    hasSpecial := false
    
    for _, char := range password {
        switch {
        case char >= 'A' && char <= 'Z':
            hasUpper = true
        case char >= 'a' && char <= 'z':
            hasLower = true
        case char >= '0' && char <= '9':
            hasNumber = true
        case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
            hasSpecial = true
        }
    }
    
    return hasUpper && hasLower && hasNumber && hasSpecial
}
```

## 🗄️ Database Integration Patterns

### **MVP Tier - Standard Database/SQL**

```go
// internal/database/database.go - Simple database setup
package database

import (
    "database/sql"
    "fmt"
    "log"
    
    _ "github.com/lib/pq"
)

type Database struct {
    db *sql.DB
}

func NewDatabase(connectionString string) (*Database, error) {
    db, err := sql.Open("postgres", connectionString)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    
    return &Database{db: db}, nil
}

func (d *Database) Close() error {
    return d.db.Close()
}

func (d *Database) GetDB() *sql.DB {
    return d.db
}

// Simple user repository
type UserRepository struct {
    db *Database
}

func NewUserRepository(db *Database) *UserRepository {
    return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(user *User) error {
    query := `INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id`
    err := r.db.db.QueryRow(query, user.Name, user.Email).Scan(&user.ID)
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }
    return nil
}

func (r *UserRepository) GetUser(id int) (*User, error) {
    query := `SELECT id, name, email, created_at FROM users WHERE id = $1`
    user := &User{}
    err := r.db.db.QueryRow(query, id).Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("user not found")
        }
        return nil, fmt.Errorf("failed to get user: %w", err)
    }
    return user, nil
}

func (r *UserRepository) GetAllUsers() ([]*User, error) {
    query := `SELECT id, name, email, created_at FROM users ORDER BY created_at DESC`
    rows, err := r.db.db.Query(query)
    if err != nil {
        return nil, fmt.Errorf("failed to get users: %w", err)
    }
    defer rows.Close()
    
    var users []*User
    for rows.Next() {
        user := &User{}
        err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.CreatedAt)
        if err != nil {
            return nil, fmt.Errorf("failed to scan user: %w", err)
        }
        users = append(users, user)
    }
    
    return users, nil
}

func (r *UserRepository) UpdateUser(user *User) error {
    query := `UPDATE users SET name = $1, email = $2 WHERE id = $3`
    _, err := r.db.db.Exec(query, user.Name, user.Email, user.ID)
    if err != nil {
        return fmt.Errorf("failed to update user: %w", err)
    }
    return nil
}

func (r *UserRepository) DeleteUser(id int) error {
    query := `DELETE FROM users WHERE id = $1`
    _, err := r.db.db.Exec(query, id)
    if err != nil {
        return fmt.Errorf("failed to delete user: %w", err)
    }
    return nil
}
```

### **CORE Tier - GORM Integration**

```go
// internal/database/gorm.go - Production GORM setup
package database

import (
    "fmt"
    "time"
    
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "gorm.io/gorm/logger"
    "go.uber.org/zap"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/models"
)

type Config struct {
    Host            string
    Port            int
    User            string
    Password        string
    DBName          string
    SSLMode         string
    MaxOpenConns    int
    MaxIdleConns    int
    ConnMaxLifetime time.Duration
    LogLevel        logger.LogLevel
}

func NewGormDB(cfg Config, log *zap.Logger) (*gorm.DB, error) {
    dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=UTC",
        cfg.Host, cfg.User, cfg.Password, cfg.DBName, cfg.Port, cfg.SSLMode)
    
    gormConfig := &gorm.Config{
        Logger: logger.New(
            &gormLoggerAdapter{logger: log},
            logger.Config{
                SlowThreshold:             time.Second,
                LogLevel:                  cfg.LogLevel,
                IgnoreRecordNotFoundError: true,
                Colorful:                  false,
            },
        ),
        NowFunc: func() time.Time {
            return time.Now().UTC()
        },
    }
    
    db, err := gorm.Open(postgres.Open(dsn), gormConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to database: %w", err)
    }
    
    // Configure connection pool
    sqlDB, err := db.DB()
    if err != nil {
        return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
    }
    
    sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
    sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
    sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
    
    // Auto-migrate models
    if err := db.AutoMigrate(
        &models.User{},
        &models.Product{},
        &models.Order{},
        &models.OrderItem{},
    ); err != nil {
        return nil, fmt.Errorf("failed to auto-migrate: %w", err)
    }
    
    log.Info("Database connected and migrated successfully")
    return db, nil
}

// GORM logger adapter
type gormLoggerAdapter struct {
    logger *zap.Logger
}

func (l *gormLoggerAdapter) Printf(format string, args ...interface{}) {
    l.logger.Info(fmt.Sprintf(format, args...))
}

// Repository base with GORM
type BaseRepository struct {
    db *gorm.DB
}

func NewBaseRepository(db *gorm.DB) *BaseRepository {
    return &BaseRepository{db: db}
}

func (r *BaseRepository) WithTx(tx *gorm.DB) *BaseRepository {
    return &BaseRepository{db: tx}
}

func (r *BaseRepository) Create(value interface{}) error {
    return r.db.Create(value).Error
}

func (r *BaseRepository) First(dest interface{}, conds ...interface{}) error {
    return r.db.First(dest, conds...).Error
}

func (r *BaseRepository) Find(dest interface{}, conds ...interface{}) error {
    return r.db.Find(dest, conds...).Error
}

func (r *BaseRepository) Update(column interface{}, value interface{}) error {
    return r.db.Update(column, value).Error
}

func (r *BaseRepository) Delete(value interface{}) error {
    return r.db.Delete(value).Error
}

func (r *BaseRepository) Where(query interface{}, args ...interface{}) *gorm.DB {
    return r.db.Where(query, args...)
}

func (r *BaseRepository) Order(value interface{}) *gorm.DB {
    return r.db.Order(value)
}

func (r *BaseRepository) Limit(limit int) *gorm.DB {
    return r.db.Limit(limit)
}

func (r *BaseRepository) Offset(offset int) *gorm.DB {
    return r.db.Offset(offset)
}

func (r *BaseRepository) Count(count *int64) *gorm.DB {
    return r.db.Count(count)
}

// Transaction helper
func (r *BaseRepository) Transaction(fn func(*gorm.DB) error) error {
    return r.db.Transaction(fn)
}
```

### **FULL Tier - Multi-Database with sqlx and Redis**

```go
// internal/database/multi_db.go - Enterprise multi-database setup
package database

import (
    "context"
    "fmt"
    "time"
    
    "github.com/jmoiron/sqlx"
    _ "github.com/lib/pq"
    "github.com/go-redis/redis/v8"
    "go.uber.org/zap"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/config"
)

type Manager struct {
    PrimaryDB *sqlx.DB
    ReadDB    *sqlx.DB
    Redis     *redis.Client
    logger    *zap.Logger
}

type Config struct {
    Primary PrimaryConfig
    Read    ReadConfig
    Redis   RedisConfig
}

type PrimaryConfig struct {
    Host            string
    Port            int
    User            string
    Password        string
    DBName          string
    SSLMode         string
    MaxOpenConns    int
    MaxIdleConns    int
    ConnMaxLifetime time.Duration
}

type ReadConfig struct {
    Host            string
    Port            int
    User            string
    Password        string
    DBName          string
    SSLMode         string
    MaxOpenConns    int
    MaxIdleConns    int
    ConnMaxLifetime time.Duration
}

type RedisConfig struct {
    Addr         string
    Password     string
    DB           int
    PoolSize     int
    MinIdleConns int
    MaxRetries   int
}

func NewManager(cfg Config, logger *zap.Logger) (*Manager, error) {
    manager := &Manager{logger: logger}
    
    // Setup primary database
    primaryDB, err := setupPostgres(cfg.Primary, "primary", logger)
    if err != nil {
        return nil, fmt.Errorf("failed to setup primary database: %w", err)
    }
    manager.PrimaryDB = primaryDB
    
    // Setup read database if configured
    if cfg.Read.Host != "" {
        readDB, err := setupPostgres(cfg.Read, "read", logger)
        if err != nil {
            return nil, fmt.Errorf("failed to setup read database: %w", err)
        }
        manager.ReadDB = readDB
    } else {
        manager.ReadDB = primaryDB // Fallback to primary
    }
    
    // Setup Redis
    redisClient, err := setupRedis(cfg.Redis, logger)
    if err != nil {
        return nil, fmt.Errorf("failed to setup Redis: %w", err)
    }
    manager.Redis = redisClient
    
    logger.Info("Database manager initialized successfully")
    return manager, nil
}

func setupPostgres(cfg PrimaryConfig, name string, logger *zap.Logger) (*sqlx.DB, error) {
    dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=UTC",
        cfg.Host, cfg.User, cfg.Password, cfg.DBName, cfg.Port, cfg.SSLMode)
    
    db, err := sqlx.Connect("postgres", dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to %s database: %w", name, err)
    }
    
    // Configure connection pool
    db.SetMaxOpenConns(cfg.MaxOpenConns)
    db.SetMaxIdleConns(cfg.MaxIdleConns)
    db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
    
    // Test connection
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping %s database: %w", name, err)
    }
    
    logger.Info(fmt.Sprintf("%s database connected successfully", name))
    return db, nil
}

func setupRedis(cfg RedisConfig, logger *zap.Logger) (*redis.Client, error) {
    rdb := redis.NewClient(&redis.Options{
        Addr:         cfg.Addr,
        Password:     cfg.Password,
        DB:           cfg.DB,
        PoolSize:     cfg.PoolSize,
        MinIdleConns: cfg.MinIdleConns,
        MaxRetries:   cfg.MaxRetries,
    })
    
    // Test connection
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := rdb.Ping(ctx).Err(); err != nil {
        return nil, fmt.Errorf("failed to ping Redis: %w", err)
    }
    
    logger.Info("Redis connected successfully")
    return rdb, nil
}

func (m *Manager) Close() error {
    var errors []error
    
    if m.PrimaryDB != nil {
        if err := m.PrimaryDB.Close(); err != nil {
            errors = append(errors, fmt.Errorf("failed to close primary DB: %w", err))
        }
    }
    
    if m.ReadDB != nil && m.ReadDB != m.PrimaryDB {
        if err := m.ReadDB.Close(); err != nil {
            errors = append(errors, fmt.Errorf("failed to close read DB: %w", err))
        }
    }
    
    if m.Redis != nil {
        if err := m.Redis.Close(); err != nil {
            errors = append(errors, fmt.Errorf("failed to close Redis: %w", err))
        }
    }
    
    if len(errors) > 0 {
        return fmt.Errorf("errors closing database connections: %v", errors)
    }
    
    return nil
}

// Health check
func (m *Manager) HealthCheck(ctx context.Context) error {
    // Check primary DB
    if err := m.PrimaryDB.PingContext(ctx); err != nil {
        return fmt.Errorf("primary database unhealthy: %w", err)
    }
    
    // Check read DB
    if err := m.ReadDB.PingContext(ctx); err != nil {
        return fmt.Errorf("read database unhealthy: %w", err)
    }
    
    // Check Redis
    if err := m.Redis.Ping(ctx).Err(); err != nil {
        return fmt.Errorf("Redis unhealthy: %w", err)
    }
    
    return nil
}

// Transaction helpers
func (m *Manager) WithPrimaryTx(ctx context.Context, fn func(*sqlx.Tx) error) error {
    tx, err := m.PrimaryDB.BeginTxx(ctx, nil)
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    
    defer func() {
        if p := recover(); p != nil {
            tx.Rollback()
            panic(p) // re-throw panic after Rollback
        } else if err != nil {
            tx.Rollback() // err is non-nil, don't change it
        } else {
            err = tx.Commit() // err is nil, if Commit returns error update err
        }
    }()
    
    err = fn(tx)
    return err
}

// Repository base with multi-database support
type Repository struct {
    manager *Manager
    logger  *zap.Logger
}

func NewRepository(manager *Manager, logger *zap.Logger) *Repository {
    return &Repository{
        manager: manager,
        logger:  logger,
    }
}

func (r *Repository) Primary() *sqlx.DB {
    return r.manager.PrimaryDB
}

func (r *Repository) Read() *sqlx.DB {
    return r.manager.ReadDB
}

func (r *Repository) Redis() *redis.Client {
    return r.manager.Redis
}

// Query helpers with automatic read/write splitting
func (r *Repository) QueryRow(ctx context.Context, query string, args ...interface{}) *sqlx.Row {
    return r.Read().QueryRowxContext(ctx, query, args...)
}

func (r *Repository) Query(ctx context.Context, query string, args ...interface{}) (*sqlx.Rows, error) {
    return r.Read().QueryxContext(ctx, query, args...)
}

func (r *Repository) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
    return r.Primary().ExecContext(ctx, query, args...)
}

func (r *Repository) Get(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
    return r.Read().GetContext(ctx, dest, query, args...)
}

func (r *Repository) Select(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
    return r.Read().SelectContext(ctx, dest, query, args...)
}

func (r *Repository) NamedExec(ctx context.Context, query string, arg interface{}) (sql.Result, error) {
    return r.Primary().NamedExecContext(ctx, query, arg)
}

func (r *Repository) NamedQuery(ctx context.Context, query string, arg interface{}) (*sqlx.Rows, error) {
    return r.Read().NamedQueryContext(ctx, query, arg)
}
```

## 🔧 Testing Strategy

### **MVP Tier - Basic Unit Testing**

```go
// internal/server/server_test.go - Simple unit tests
package server

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestServer_GetUsers(t *testing.T) {
    server := NewServer()
    
    req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
    w := httptest.NewRecorder()
    
    server.handleUsers(w, req)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }
    
    var users []User
    if err := json.NewDecoder(w.Body).Decode(&users); err != nil {
        t.Errorf("Failed to decode response: %v", err)
    }
    
    if len(users) != 2 {
        t.Errorf("Expected 2 users, got %d", len(users))
    }
}

func TestServer_CreateUser(t *testing.T) {
    server := NewServer()
    
    user := User{
        Name:  "Test User",
        Email: "test@example.com",
    }
    
    body, _ := json.Marshal(user)
    req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    w := httptest.NewRecorder()
    
    server.handleUsers(w, req)
    
    if w.Code != http.StatusCreated {
        t.Errorf("Expected status 201, got %d", w.Code)
    }
    
    var createdUser User
    if err := json.NewDecoder(w.Body).Decode(&createdUser); err != nil {
        t.Errorf("Failed to decode response: %v", err)
    }
    
    if createdUser.Name != user.Name {
        t.Errorf("Expected name %s, got %s", user.Name, createdUser.Name)
    }
    
    if createdUser.Email != user.Email {
        t.Errorf("Expected email %s, got %s", user.Email, createdUser.Email)
    }
}

func TestServer_GetUser(t *testing.T) {
    server := NewServer()
    
    req := httptest.NewRequest(http.MethodGet, "/api/users/1", nil)
    w := httptest.NewRecorder()
    
    server.handleUser(w, req, 1)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }
    
    var user User
    if err := json.NewDecoder(w.Body).Decode(&user); err != nil {
        t.Errorf("Failed to decode response: %v", err)
    }
    
    if user.ID != 1 {
        t.Errorf("Expected user ID 1, got %d", user.ID)
    }
}

func TestServer_GetUserNotFound(t *testing.T) {
    server := NewServer()
    
    req := httptest.NewRequest(http.MethodGet, "/api/users/999", nil)
    w := httptest.NewRecorder()
    
    server.handleUser(w, req, 999)
    
    if w.Code != http.StatusNotFound {
        t.Errorf("Expected status 404, got %d", w.Code)
    }
}

func TestServer_UpdateUser(t *testing.T) {
    server := NewServer()
    
    updatedUser := User{
        Name:  "Updated User",
        Email: "updated@example.com",
    }
    
    body, _ := json.Marshal(updatedUser)
    req := httptest.NewRequest(http.MethodPut, "/api/users/1", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    w := httptest.NewRecorder()
    
    server.handleUser(w, req, 1)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }
    
    var user User
    if err := json.NewDecoder(w.Body).Decode(&user); err != nil {
        t.Errorf("Failed to decode response: %v", err)
    }
    
    if user.Name != updatedUser.Name {
        t.Errorf("Expected name %s, got %s", updatedUser.Name, user.Name)
    }
}

func TestServer_DeleteUser(t *testing.T) {
    server := NewServer()
    
    req := httptest.NewRequest(http.MethodDelete, "/api/users/1", nil)
    w := httptest.NewRecorder()
    
    server.handleUser(w, req, 1)
    
    if w.Code != http.StatusNoContent {
        t.Errorf("Expected status 204, got %d", w.Code)
    }
    
    // Verify user is deleted
    req = httptest.NewRequest(http.MethodGet, "/api/users/1", nil)
    w = httptest.NewRecorder()
    
    server.handleUser(w, req, 1)
    
    if w.Code != http.StatusNotFound {
        t.Errorf("Expected status 404 after delete, got %d", w.Code)
    }
}

// Benchmark tests
func BenchmarkServer_GetUsers(b *testing.B) {
    server := NewServer()
    
    for i := 0; i < b.N; i++ {
        req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
        w := httptest.NewRecorder()
        server.handleUsers(w, req)
    }
}

func BenchmarkServer_CreateUser(b *testing.B) {
    server := NewServer()
    user := User{Name: "Test User", Email: "test@example.com"}
    body, _ := json.Marshal(user)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBuffer(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        server.handleUsers(w, req)
    }
}
```

### **CORE Tier - Table-Driven Tests with Mocks**

```go
// internal/services/user_service_test.go - Production testing
package services

import (
    "context"
    "errors"
    "testing"
    "time"
    
    "github.com/golang/mock/gomock"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/dto"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/models"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/repositories/mocks"
)

func TestUserService_GetUserByID(t *testing.T) {
    tests := []struct {
        name          string
        userID        uint
        mockSetup     func(repo *mocks.MockUserRepository)
        expectedUser  *models.User
        expectedError error
    }{
        {
            name:   "success - user found",
            userID: 1,
            mockSetup: func(repo *mocks.MockUserRepository) {
                user := &models.User{
                    ID:        1,
                    Name:      "John Doe",
                    Email:     "john@example.com",
                    CreatedAt: time.Now(),
                }
                repo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(user, nil)
            },
            expectedUser: &models.User{
                ID:    1,
                Name:  "John Doe",
                Email: "john@example.com",
            },
            expectedError: nil,
        },
        {
            name:   "error - user not found",
            userID: 999,
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByID(gomock.Any(), uint(999)).Return(nil, ErrUserNotFound)
            },
            expectedUser:  nil,
            expectedError: ErrUserNotFound,
        },
        {
            name:   "error - database error",
            userID: 1,
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(nil, errors.New("database error"))
            },
            expectedUser:  nil,
            expectedError: errors.New("database error"),
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()
            
            mockRepo := mocks.NewMockUserRepository(ctrl)
            tt.mockSetup(mockRepo)
            
            service := NewUserService(mockRepo)
            
            user, err := service.GetUserByID(context.Background(), tt.userID)
            
            if tt.expectedError != nil {
                assert.Error(t, err)
                assert.Equal(t, tt.expectedError, err)
                assert.Nil(t, user)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedUser.ID, user.ID)
                assert.Equal(t, tt.expectedUser.Name, user.Name)
                assert.Equal(t, tt.expectedUser.Email, user.Email)
            }
        })
    }
}

func TestUserService_CreateUser(t *testing.T) {
    tests := []struct {
        name          string
        request       *dto.CreateUserRequest
        mockSetup     func(repo *mocks.MockUserRepository)
        expectedUser  *models.User
        expectedError error
    }{
        {
            name: "success - valid user",
            request: &dto.CreateUserRequest{
                Name:     "John Doe",
                Email:    "john@example.com",
                Password: "password123",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByEmail(gomock.Any(), "john@example.com").Return(nil, ErrUserNotFound)
                repo.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, user *models.User) error {
                    user.ID = 1
                    user.CreatedAt = time.Now()
                    return nil
                })
            },
            expectedUser: &models.User{
                ID:    1,
                Name:  "John Doe",
                Email: "john@example.com",
            },
            expectedError: nil,
        },
        {
            name: "error - user already exists",
            request: &dto.CreateUserRequest{
                Name:     "John Doe",
                Email:    "john@example.com",
                Password: "password123",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                existingUser := &models.User{
                    ID:    1,
                    Name:  "John Doe",
                    Email: "john@example.com",
                }
                repo.EXPECT().GetByEmail(gomock.Any(), "john@example.com").Return(existingUser, nil)
            },
            expectedUser:  nil,
            expectedError: ErrUserAlreadyExists,
        },
        {
            name: "error - database error on create",
            request: &dto.CreateUserRequest{
                Name:     "John Doe",
                Email:    "john@example.com",
                Password: "password123",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByEmail(gomock.Any(), "john@example.com").Return(nil, ErrUserNotFound)
                repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("database error"))
            },
            expectedUser:  nil,
            expectedError: errors.New("database error"),
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()
            
            mockRepo := mocks.NewMockUserRepository(ctrl)
            tt.mockSetup(mockRepo)
            
            service := NewUserService(mockRepo)
            
            user, err := service.CreateUser(context.Background(), tt.request)
            
            if tt.expectedError != nil {
                assert.Error(t, err)
                assert.Equal(t, tt.expectedError, err)
                assert.Nil(t, user)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedUser.ID, user.ID)
                assert.Equal(t, tt.expectedUser.Name, user.Name)
                assert.Equal(t, tt.expectedUser.Email, user.Email)
                assert.NotEmpty(t, user.PasswordHash)
                assert.NotEmpty(t, user.CreatedAt)
            }
        })
    }
}

func TestUserService_UpdateUser(t *testing.T) {
    tests := []struct {
        name          string
        userID        uint
        request       *dto.UpdateUserRequest
        mockSetup     func(repo *mocks.MockUserRepository)
        expectedUser  *models.User
        expectedError error
    }{
        {
            name:   "success - valid update",
            userID: 1,
            request: &dto.UpdateUserRequest{
                Name:  "Updated Name",
                Email: "updated@example.com",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                existingUser := &models.User{
                    ID:        1,
                    Name:      "John Doe",
                    Email:     "john@example.com",
                    CreatedAt: time.Now(),
                }
                repo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(existingUser, nil)
                repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
            },
            expectedUser: &models.User{
                ID:    1,
                Name:  "Updated Name",
                Email: "updated@example.com",
            },
            expectedError: nil,
        },
        {
            name:   "error - user not found",
            userID: 999,
            request: &dto.UpdateUserRequest{
                Name:  "Updated Name",
                Email: "updated@example.com",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByID(gomock.Any(), uint(999)).Return(nil, ErrUserNotFound)
            },
            expectedUser:  nil,
            expectedError: ErrUserNotFound,
        },
        {
            name:   "error - database error on update",
            userID: 1,
            request: &dto.UpdateUserRequest{
                Name:  "Updated Name",
                Email: "updated@example.com",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                existingUser := &models.User{
                    ID:        1,
                    Name:      "John Doe",
                    Email:     "john@example.com",
                    CreatedAt: time.Now(),
                }
                repo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(existingUser, nil)
                repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("database error"))
            },
            expectedUser:  nil,
            expectedError: errors.New("database error"),
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()
            
            mockRepo := mocks.NewMockUserRepository(ctrl)
            tt.mockSetup(mockRepo)
            
            service := NewUserService(mockRepo)
            
            user, err := service.UpdateUser(context.Background(), tt.userID, tt.request)
            
            if tt.expectedError != nil {
                assert.Error(t, err)
                assert.Equal(t, tt.expectedError, err)
                assert.Nil(t, user)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedUser.ID, user.ID)
                assert.Equal(t, tt.expectedUser.Name, user.Name)
                assert.Equal(t, tt.expectedUser.Email, user.Email)
            }
        })
    }
}

// Integration tests
func TestUserService_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }
    
    // Setup test database
    db := setupTestDB(t)
    defer cleanupTestDB(t, db)
    
    // Setup repository
    repo := repositories.NewUserRepository(db)
    
    // Setup service
    service := NewUserService(repo)
    
    ctx := context.Background()
    
    // Test create user
    req := &dto.CreateUserRequest{
        Name:     "Integration Test User",
        Email:    "integration@example.com",
        Password: "password123",
    }
    
    user, err := service.CreateUser(ctx, req)
    require.NoError(t, err)
    assert.NotZero(t, user.ID)
    assert.Equal(t, req.Name, user.Name)
    assert.Equal(t, req.Email, user.Email)
    
    // Test get user
    retrievedUser, err := service.GetUserByID(ctx, user.ID)
    require.NoError(t, err)
    assert.Equal(t, user.ID, retrievedUser.ID)
    assert.Equal(t, user.Name, retrievedUser.Name)
    assert.Equal(t, user.Email, retrievedUser.Email)
    
    // Test update user
    updateReq := &dto.UpdateUserRequest{
        Name:  "Updated Integration User",
        Email: "updated@example.com",
    }
    
    updatedUser, err := service.UpdateUser(ctx, user.ID, updateReq)
    require.NoError(t, err)
    assert.Equal(t, updateReq.Name, updatedUser.Name)
    assert.Equal(t, updateReq.Email, updatedUser.Email)
    
    // Test delete user
    err = service.DeleteUser(ctx, user.ID)
    require.NoError(t, err)
    
    // Verify user is deleted
    _, err = service.GetUserByID(ctx, user.ID)
    assert.Equal(t, ErrUserNotFound, err)
}

// Benchmark tests
func BenchmarkUserService_CreateUser(b *testing.B) {
    ctrl := gomock.NewController(b)
    defer ctrl.Finish()
    
    mockRepo := mocks.NewMockUserRepository(ctrl)
    mockRepo.EXPECT().GetByEmail(gomock.Any(), gomock.Any()).Return(nil, ErrUserNotFound).AnyTimes()
    mockRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
    
    service := NewUserService(mockRepo)
    
    req := &dto.CreateUserRequest{
        Name:     "Benchmark User",
        Email:    "benchmark@example.com",
        Password: "password123",
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := service.CreateUser(context.Background(), req)
        if err != nil {
            b.Fatalf("CreateUser failed: %v", err)
        }
    }
}

func BenchmarkUserService_GetUserByID(b *testing.B) {
    ctrl := gomock.NewController(b)
    defer ctrl.Finish()
    
    mockRepo := mocks.NewMockUserRepository(ctrl)
    user := &models.User{
        ID:    1,
        Name:  "Test User",
        Email: "test@example.com",
    }
    mockRepo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(user, nil).AnyTimes()
    
    service := NewUserService(mockRepo)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := service.GetUserByID(context.Background(), 1)
        if err != nil {
            b.Fatalf("GetUserByID failed: %v", err)
        }
    }
}

// Helper functions for integration tests
func setupTestDB(t *testing.T) *sqlx.DB {
    // Setup in-memory test database or test container
    db, err := sqlx.Connect("postgres", "postgres://test:test@localhost:5432/test_db?sslmode=disable")
    require.NoError(t, err)
    
    // Run migrations
    err = runMigrations(db)
    require.NoError(t, err)
    
    return db
}

func cleanupTestDB(t *testing.T, db *sqlx.DB) {
    // Clean up test data
    _, err := db.Exec("DELETE FROM users")
    require.NoError(t, err)
    
    db.Close()
}

func runMigrations(db *sqlx.DB) error {
    // Run database migrations for tests
    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    `)
    return err
}
```

### **FULL Tier - Comprehensive Testing with TestContainers**

```go
// internal/services/user_service_test.go - Enterprise testing
package services

import (
    "context"
    "fmt"
    "testing"
    "time"
    
    "github.com/golang/mock/gomock"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/wait"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/config"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/database"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/dto"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/models"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/repositories"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/repositories/mocks"
)

// Test suite for comprehensive testing
type UserServiceTestSuite struct {
    suite.Suite
    container testcontainers.Container
    db        *sqlx.DB
    service   UserService
    repo      repositories.UserRepository
}

func (suite *UserServiceTestSuite) SetupSuite() {
    // Setup PostgreSQL test container
    ctx := context.Background()
    req := testcontainers.ContainerRequest{
        Image:        "postgres:15-alpine",
        ExposedPorts: []string{"5432/tcp"},
        Env: map[string]string{
            "POSTGRES_DB":       "testdb",
            "POSTGRES_USER":     "testuser",
            "POSTGRES_PASSWORD": "testpass",
        },
        WaitingFor: wait.ForLog("database system is ready to accept connections"),
    }
    
    container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
        ContainerRequest: req,
        Started:          true,
    })
    suite.Require().NoError(err)
    
    suite.container = container
    
    // Get database connection details
    host, err := container.Host(ctx)
    suite.Require().NoError(err)
    
    port, err := container.MappedPort(ctx, "5432")
    suite.Require().NoError(err)
    
    // Connect to test database
    dsn := fmt.Sprintf("postgres://testuser:testpass@%s:%s/testdb?sslmode=disable", host, port.Port())
    db, err := sqlx.Connect("postgres", dsn)
    suite.Require().NoError(err)
    
    suite.db = db
    
    // Run migrations
    err = runTestMigrations(db)
    suite.Require().NoError(err)
    
    // Setup repository and service
    suite.repo = repositories.NewUserRepository(db)
    suite.service = NewUserService(suite.repo)
}

func (suite *UserServiceTestSuite) TearDownSuite() {
    if suite.db != nil {
        suite.db.Close()
    }
    if suite.container != nil {
        ctx := context.Background()
        suite.container.Terminate(ctx)
    }
}

func (suite *UserServiceTestSuite) SetupTest() {
    // Clean up database before each test
    _, err := suite.db.Exec("DELETE FROM users")
    suite.Require().NoError(err)
}

func (suite *UserServiceTestSuite) TestCreateUser_Success() {
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    user, err := suite.service.CreateUser(context.Background(), req)
    
    suite.NoError(err)
    suite.NotZero(user.ID)
    suite.Equal(req.Name, user.Name)
    suite.Equal(req.Email, user.Email)
    suite.NotEmpty(user.PasswordHash)
    suite.NotZero(user.CreatedAt)
}

func (suite *UserServiceTestSuite) TestCreateUser_DuplicateEmail() {
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    // Create first user
    _, err := suite.service.CreateUser(context.Background(), req)
    suite.NoError(err)
    
    // Try to create user with same email
    _, err = suite.service.CreateUser(context.Background(), req)
    
    suite.Error(err)
    suite.Equal(ErrUserAlreadyExists, err)
}

func (suite *UserServiceTestSuite) TestGetUserByID_Success() {
    // Create user first
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    createdUser, err := suite.service.CreateUser(context.Background(), req)
    suite.NoError(err)
    
    // Get user by ID
    user, err := suite.service.GetUserByID(context.Background(), createdUser.ID)
    
    suite.NoError(err)
    suite.Equal(createdUser.ID, user.ID)
    suite.Equal(createdUser.Name, user.Name)
    suite.Equal(createdUser.Email, user.Email)
}

func (suite *UserServiceTestSuite) TestUpdateUser_Success() {
    // Create user first
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    createdUser, err := suite.service.CreateUser(context.Background(), req)
    suite.NoError(err)
    
    // Update user
    updateReq := &dto.UpdateUserRequest{
        Name:  "Updated User",
        Email: "updated@example.com",
    }
    
    updatedUser, err := suite.service.UpdateUser(context.Background(), createdUser.ID, updateReq)
    
    suite.NoError(err)
    suite.Equal(updateReq.Name, updatedUser.Name)
    suite.Equal(updateReq.Email, updatedUser.Email)
    suite.Equal(createdUser.ID, updatedUser.ID)
}

func (suite *UserServiceTestSuite) TestDeleteUser_Success() {
    // Create user first
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    createdUser, err := suite.service.CreateUser(context.Background(), req)
    suite.NoError(err)
    
    // Delete user
    err = suite.service.DeleteUser(context.Background(), createdUser.ID)
    suite.NoError(err)
    
    // Verify user is deleted
    _, err = suite.service.GetUserByID(context.Background(), createdUser.ID)
    suite.Error(err)
    suite.Equal(ErrUserNotFound, err)
}

func (suite *UserServiceTestSuite) TestGetUsersWithPagination_Success() {
    // Create test users
    for i := 1; i <= 25; i++ {
        req := &dto.CreateUserRequest{
            Name:     fmt.Sprintf("User %d", i),
            Email:    fmt.Sprintf("user%d@example.com", i),
            Password: "password123",
        }
        _, err := suite.service.CreateUser(context.Background(), req)
        suite.NoError(err)
    }
    
    // Test first page
    users, total, err := suite.service.GetUsers(context.Background(), 1, 10)
    
    suite.NoError(err)
    suite.Len(users, 10)
    suite.Equal(25, total)
    suite.Equal("User 25", users[0].Name) // Should be ordered by created_at DESC
}

// Performance tests
func (suite *UserServiceTestSuite) TestPerformance_BulkCreate() {
    start := time.Now()
    
    for i := 1; i <= 1000; i++ {
        req := &dto.CreateUserRequest{
            Name:     fmt.Sprintf("Perf User %d", i),
            Email:    fmt.Sprintf("perfuser%d@example.com", i),
            Password: "password123",
        }
        _, err := suite.service.CreateUser(context.Background(), req)
        suite.NoError(err)
    }
    
    duration := time.Since(start)
    suite.Less(duration, 10*time.Second, "Bulk create should complete within 10 seconds")
    
    fmt.Printf("Created 1000 users in %v\n", duration)
}

func (suite *UserServiceTestSuite) TestPerformance_Pagination() {
    // Create 10,000 users
    for i := 1; i <= 10000; i++ {
        req := &dto.CreateUserRequest{
            Name:     fmt.Sprintf("User %d", i),
            Email:    fmt.Sprintf("user%d@example.com", i),
            Password: "password123",
        }
        _, err := suite.service.CreateUser(context.Background(), req)
        suite.NoError(err)
    }
    
    start := time.Now()
    
    // Test pagination performance
    for page := 1; page <= 100; page++ {
        _, _, err := suite.service.GetUsers(context.Background(), page, 100)
        suite.NoError(err)
    }
    
    duration := time.Since(start)
    suite.Less(duration, 5*time.Second, "Pagination should complete within 5 seconds")
    
    fmt.Printf("Paginated 10,000 users in %v\n", duration)
}

// Concurrent tests
func (suite *UserServiceTestSuite) TestConcurrent_CreateUsers() {
    const numGoroutines = 100
    const numUsersPerGoroutine = 10
    
    var wg sync.WaitGroup
    errors := make(chan error, numGoroutines)
    
    for i := 0; i < numGoroutines; i++ {
        wg.Add(1)
        go func(goroutineID int) {
            defer wg.Done()
            
            for j := 1; j <= numUsersPerGoroutine; j++ {
                req := &dto.CreateUserRequest{
                    Name:     fmt.Sprintf("Concurrent User %d-%d", goroutineID, j),
                    Email:    fmt.Sprintf("concurrent%d-%d@example.com", goroutineID, j),
                    Password: "password123",
                }
                
                _, err := suite.service.CreateUser(context.Background(), req)
                if err != nil {
                    errors <- err
                    return
                }
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    // Check for errors
    for err := range errors {
        suite.NoError(err)
    }
    
    // Verify all users were created
    users, total, err := suite.service.GetUsers(context.Background(), 1, 1000)
    suite.NoError(err)
    suite.Equal(numGoroutines*numUsersPerGoroutine, total)
    suite.Len(users, numGoroutines*numUsersPerGoroutine)
}

// Run the test suite
func TestUserServiceSuite(t *testing.T) {
    suite.Run(t, new(UserServiceTestSuite))
}

// Mock-based unit tests for edge cases
func TestUserService_MockBased(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()
    
    mockRepo := mocks.NewMockUserRepository(ctrl)
    service := NewUserService(mockRepo)
    
    t.Run("GetUserByID_DatabaseError", func(t *testing.T) {
        mockRepo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(nil, errors.New("database connection lost"))
        
        user, err := service.GetUserByID(context.Background(), 1)
        
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "database connection lost")
        assert.Nil(t, user)
    })
    
    t.Run("CreateUser_EmailValidation", func(t *testing.T) {
        req := &dto.CreateUserRequest{
            Name:     "Test User",
            Email:    "invalid-email",
            Password: "password123",
        }
        
        user, err := service.CreateUser(context.Background(), req)
        
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "invalid email format")
        assert.Nil(t, user)
    })
    
    t.Run("UpdateUser_NoChanges", func(t *testing.T) {
        existingUser := &models.User{
            ID:        1,
            Name:      "Test User",
            Email:     "test@example.com",
            CreatedAt: time.Now(),
        }
        
        mockRepo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(existingUser, nil)
        mockRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
        
        req := &dto.UpdateUserRequest{
            Name:  "Test User",
            Email: "test@example.com",
        }
        
        user, err := service.UpdateUser(context.Background(), 1, req)
        
        assert.NoError(t, err)
        assert.Equal(t, existingUser.Name, user.Name)
        assert.Equal(t, existingUser.Email, user.Email)
    })
}

// Helper functions
func runTestMigrations(db *sqlx.DB) error {
    migrations := []string{
        `CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );`,
        `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
        `CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);`,
    }
    
    for _, migration := range migrations {
        if _, err := db.Exec(migration); err != nil {
            return fmt.Errorf("failed to run migration: %w", err)
        }
    }
    
    return nil
}
```

---

**Go Version**: [GO_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
