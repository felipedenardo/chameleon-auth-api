package auth

import (
	"errors"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/auth"
	httphelpers "github.com/felipedenardo/chameleon-common/pkg/http"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
		if errors.Is(err, errors.New("email already exists")) {
			httphelpers.RespondDomainFail(c, err.Error())
			return
		}
		httphelpers.RespondInternalError(c, err)
		return
	}

	responseDTO := ToUserResponse(userDomain)
	httphelpers.RespondCreated(c, responseDTO)
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
		httphelpers.RespondUnauthorized(c, err.Error())
		return
	}

	responseDTO := LoginResponse{
		Token: token,
		User:  ToUserResponse(userDomain),
	}

	httphelpers.RespondOK(c, responseDTO)
}

// ChangePassword godoc
// @Summary Altera a senha do usuário logado
// @Tags Auth
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Router /auth/change-password [post]
func (h *Handler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest

	userIDString, exists := c.Get("userID")
	if !exists {
		httphelpers.RespondUnauthorized(c, "Authentication context missing")
		return
	}

	userID, err := uuid.Parse(userIDString.(string))
	if err != nil {
		httphelpers.RespondParamError(c, "user_id", "Invalid user id in token")
		return
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	err = h.service.ChangePassword(
		c.Request.Context(),
		userID,
		req.CurrentPassword,
		req.NewPassword,
	)

	if err != nil {
		if errors.Is(err, errors.New("invalid current password")) ||
			errors.Is(err, errors.New("new password cannot be the same as the current password")) {
			httphelpers.RespondDomainFail(c, err.Error())
			return
		}
		httphelpers.RespondInternalError(c, err)
		return
	}

	httphelpers.RespondOK(c, gin.H{"message": "Password changed successfully"})
}
