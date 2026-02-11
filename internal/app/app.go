package app

import (
	_ "github.com/felipedenardo/chameleon-auth-api/docs"
	authhandler "github.com/felipedenardo/chameleon-auth-api/internal/api/handler/auth"
	"github.com/felipedenardo/chameleon-auth-api/internal/config"
	authdomain "github.com/felipedenardo/chameleon-auth-api/internal/domain/auth"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/user"
	"github.com/felipedenardo/chameleon-auth-api/internal/infra/database/postgresql/repository"
	redisrepository "github.com/felipedenardo/chameleon-auth-api/internal/infra/database/redis"
	"github.com/felipedenardo/chameleon-common/pkg/middleware"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
)

type HandlerContainer struct {
	AuthHandler *authhandler.Handler
	RedisClient *redis.Client
	UserRepo    user.IRepository
}

func NewHandlerContainer(db *gorm.DB, cfg *config.Config, redisClient *redis.Client) *HandlerContainer {
	userRepo := repository.NewUserRepository(db)
	return &HandlerContainer{
		AuthHandler: newAuthHandler(cfg, redisClient, userRepo),
		RedisClient: redisClient,
		UserRepo:    userRepo,
	}
}

func newAuthHandler(cfg *config.Config, redisClient *redis.Client, userRepo user.IRepository) *authhandler.Handler {
	cacheRepo := redisrepository.NewCacheRepository(redisClient)
	authService := authdomain.NewAuthService(userRepo, cacheRepo, cfg.JWTSecret)
	return authhandler.NewAuthHandler(authService)
}

func SetupRouter(handlers *HandlerContainer, cfg *config.Config) *gin.Engine {
	r := gin.Default()

	cacheRepo := redisrepository.NewCacheRepository(handlers.RedisClient)
	tokenManager := redisrepository.NewTokenVersionManager(cacheRepo, handlers.UserRepo)

	basePath := r.Group(cfg.AppBasePath)
	{
		basePath.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

		api := basePath.Group("/api/v1")
		{
			public := api.Group("/")
			{
				public.POST("/register", handlers.AuthHandler.Register)
				public.POST("/login", handlers.AuthHandler.Login)
				public.POST("/forgot-password", handlers.AuthHandler.ForgotPassword)
				public.POST("/reset-password", handlers.AuthHandler.ResetPassword)
			}

			authMiddleware := middleware.AuthMiddleware(cfg.JWTSecret, cacheRepo, tokenManager)

			protected := api.Group("/").Use(authMiddleware)
			{
				protected.POST("/change-password", handlers.AuthHandler.ChangePassword)
				protected.POST("/logout", handlers.AuthHandler.Logout)
				protected.POST("/deactivate", handlers.AuthHandler.DeactivateSelf)
			}

			admin := api.Group("/admin").Use(authMiddleware)
			{
				admin.PUT("/users/:id/status", handlers.AuthHandler.UpdateUserStatus)
			}

			api.GET("/health", func(c *gin.Context) {
				c.JSON(200, gin.H{"status": "ok", "service": "auth-api"})
			})
		}
	}

	return r
}
