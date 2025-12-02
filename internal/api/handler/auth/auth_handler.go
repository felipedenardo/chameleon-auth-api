package auth

import (
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/auth"
	httphelpers "github.com/felipedenardo/chameleon-common/pkg/http"
	"github.com/felipedenardo/chameleon-common/pkg/response"
	"github.com/gin-gonic/gin"
	"net/http"
)

type Handler struct {
	service auth.IService
}

func NewAuthHandler(s auth.IService) *Handler {
	return &Handler{service: s}
}

// Register godoc
// @Summary Registra um novo usuário
// @Tags Auth
// @Accept json
// @Produce json
// @Success 201 {object} response.Standard
// @Failure 400 {object} response.Standard
// @Failure 500 {object} response.Standard
// @Router /auth/register [post]
func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	userDomain, err := h.service.Register(c.Request.Context(), req.Name, req.Email, req.Password, req.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.NewInternalErr())
		return
	}

	responseDTO := ToUserResponse(userDomain)
	c.JSON(http.StatusCreated, response.NewCreated(responseDTO))
}

// Login godoc
// @Summary Autenticar usuário
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} response.Standard
// @Failure 401 {object} response.Standard
// @Failure 500 {object} response.Standard
// @Router /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	token, userDomain, err := h.service.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.NewErrorCustom(err.Error()))
		return
	}

	responseDTO := LoginResponse{
		Token: token,
		User:  ToUserResponse(userDomain),
	}
	c.JSON(http.StatusOK, response.NewSuccess(responseDTO))
}
