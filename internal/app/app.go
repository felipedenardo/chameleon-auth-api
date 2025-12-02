package app

import (
	_ "github.com/felipedenardo/chameleon-auth-api/docs"
	authhandler "github.com/felipedenardo/chameleon-auth-api/internal/api/handler/auth"
	"github.com/felipedenardo/chameleon-auth-api/internal/config"
	authdomain "github.com/felipedenardo/chameleon-auth-api/internal/domain/auth"
	"github.com/felipedenardo/chameleon-auth-api/internal/infra/database/postgresql/repository"
	"github.com/felipedenardo/chameleon-common/pkg/middleware"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
)

type HandlerContainer struct {
	AuthHandler *authhandler.Handler
}

func newAuthHandler(db *gorm.DB, cfg *config.Config) *authhandler.Handler {
	userRepo := repository.NewUserRepository(db)
	authService := authdomain.NewAuthService(userRepo, cfg.JWTSecret)
	return authhandler.NewAuthHandler(authService)
}

func NewHandlerContainer(db *gorm.DB, cfg *config.Config) *HandlerContainer {
	return &HandlerContainer{
		AuthHandler: newAuthHandler(db, cfg),
	}
}

func SetupRouter(handlers *HandlerContainer, cfg *config.Config) *gin.Engine {
	r := gin.Default()

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api := r.Group("/api/v1")
	{
		authRoutes := api.Group("/auth")
		{
			authRoutes.POST("/register", handlers.AuthHandler.Register)
			authRoutes.POST("/login", handlers.AuthHandler.Login)
		}

		authMiddleware := middleware.AuthMiddleware(cfg.JWTSecret)
		protectedAuthRoutes := api.Group("/auth").Use(authMiddleware)
		{
			protectedAuthRoutes.POST("/change-password", handlers.AuthHandler.ChangePassword)
		}

		api.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok", "service": "auth-api"})
		})
	}

	return r
}
