package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/felipedenardo/chameleon-auth-api/internal/config"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/auth"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/user"
	"github.com/felipedenardo/chameleon-auth-api/internal/infra/ratelimit"
	httphelpers "github.com/felipedenardo/chameleon-common/pkg/http"
	"github.com/felipedenardo/chameleon-common/pkg/middleware"
	"github.com/felipedenardo/chameleon-common/pkg/validation"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	service  user.IService
	cfg      *config.Config
	limiter  *ratelimit.Limiter
	pwUpper  *regexp.Regexp
	pwLower  *regexp.Regexp
	pwSymbol *regexp.Regexp
}

func NewAuthHandler(s user.IService, cfg *config.Config, limiter *ratelimit.Limiter) *Handler {
	return &Handler{
		service:  s,
		cfg:      cfg,
		limiter:  limiter,
		pwUpper:  regexp.MustCompile(`[A-Z]`),
		pwLower:  regexp.MustCompile(`[a-z]`),
		pwSymbol: regexp.MustCompile(`[^A-Za-z0-9]`),
	}
}

// Register godoc
// @Summary Registra um novo usuário
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Dados para registro de novo usuário"
// @Success 201 {object} response.Standard{data=UserResponse}
// @Failure 400 {object} response.Standard
// @Failure 500 {object} response.Standard
// @Router /auth/register [post]
func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	if !h.isStrongPassword(req.Password) {
		httphelpers.RespondDomainFail(c, "Senha deve ter no mínimo 8 caracteres, 1 maiúscula, 1 minúscula e 1 especial.")
		return
	}

	userDomain, err := h.service.Register(c.Request.Context(), req.Name, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrEmailAlreadyExists) {
			httphelpers.RespondDomainFail(c, "Não foi possível concluir o cadastro.")
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
// @Param request body LoginRequest true "Credenciais do usuário para login"
// @Success 200 {object} response.Standard{data=LoginResponse}
// @Failure 401 {object} response.Standard
// @Failure 500 {object} response.Standard
// @Router /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	if err := h.checkRateLimit(c, "login", req.Email, h.cfg.LoginRateLimit, h.cfg.LoginRateWindowSec); err != nil {
		return
	}

	token, refreshToken, userDomain, err := h.service.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		httphelpers.RespondUnauthorized(c, "Credenciais inválidas.")
		return
	}

	responseDTO := LoginResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         ToUserResponse(userDomain),
	}

	httphelpers.RespondOK(c, responseDTO)
}

// ChangePassword godoc
// @Summary Altera a senha do usuário logado
// @Tags Auth
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param request body ChangePasswordRequest true "Dados para alteração de senha"
// @Success 200 {object} response.Standard
// @Router /auth/change-password [post]
func (h *Handler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest

	userIDString, exists := middleware.RequireUserID(c)
	if !exists {
		return
	}

	userID, err := uuid.Parse(userIDString)
	if err != nil {
		httphelpers.RespondParamError(c, "user_id", "Invalid user id in token")
		return
	}

	if err = c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	if !h.isStrongPassword(req.NewPassword) {
		httphelpers.RespondDomainFail(c, "Senha deve ter no mínimo 8 caracteres, 1 maiúscula, 1 minúscula e 1 especial.")
		return
	}

	token, exists := middleware.RequireRawToken(c)
	if !exists {
		return
	}

	err = h.service.ChangePassword(
		c.Request.Context(),
		userID,
		req.CurrentPassword,
		req.NewPassword,
		token,
	)

	if err != nil {
		if errors.Is(err, auth.ErrInvalidCurrentPassword) ||
			errors.Is(err, auth.ErrSamePassword) {
			httphelpers.RespondDomainFail(c, "Não foi possível alterar a senha.")
			return
		}
		httphelpers.RespondInternalError(c, err)
		return
	}

	httphelpers.RespondOK(c, gin.H{"message": "Password changed successfully"})
}

// Logout revoga o token JWT, adicionando-o à blacklist no Redis.
// @Summary Revogar Token
// @Description Adiciona o JWT à blacklist, invalidando a sessão imediatamente.
// @Tags Auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body LogoutRequest true "Refresh token"
// @Success 200 {object} response.Standard
// @Failure 400 {object} response.Standard
// @Failure 401 {object} response.Standard
// @Router /auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	var req LogoutRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	token, exists := middleware.RequireRawToken(c)
	if !exists {
		return
	}

	err := h.service.Logout(c.Request.Context(), token, req.RefreshToken)

	if err != nil {
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			httphelpers.RespondUnauthorized(c, "Sessão inválida.")
			return
		}
		httphelpers.RespondInternalError(c, err)
		return
	}

	httphelpers.RespondOK(c, gin.H{"message": "Sessão encerrada com sucesso."})
}

// LogoutAll revoga todas as sessões do usuário atual.
// @Summary Revogar todas as sessões
// @Description Incrementa a versão do token, invalidando todos os tokens do usuário.
// @Tags Auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} response.Standard
// @Failure 400 {object} response.Standard
// @Failure 401 {object} response.Standard
// @Router /auth/logout-all [post]
func (h *Handler) LogoutAll(c *gin.Context) {
	userIDString, exists := middleware.RequireUserID(c)
	if !exists {
		return
	}

	userID, err := uuid.Parse(userIDString)
	if err != nil {
		httphelpers.RespondParamError(c, "user_id", "Invalid user id in token")
		return
	}

	token, exists := middleware.RequireRawToken(c)
	if !exists {
		return
	}

	err = h.service.LogoutAll(c.Request.Context(), userID, token)
	if err != nil {
		httphelpers.RespondInternalError(c, err)
		return
	}

	httphelpers.RespondOK(c, gin.H{"message": "Todas as sessões foram encerradas com sucesso."})
}

// ForgotPassword godoc
// @Summary Iniciar recuperação de senha
// @Description Recebe o e-mail do usuário e envia um token de reset
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "E-mail do usuário"
// @Success 200 {object} response.Standard
// @Failure 400 {object} response.Standard
// @Failure 500 {object} response.Standard
// @Router /auth/forgot-password [post]
func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	if err := h.checkRateLimit(c, "forgot", req.Email, h.cfg.ForgotRateLimit, h.cfg.ForgotRateWindowSec); err != nil {
		return
	}

	if errs := validation.ValidateRequest(req); errs != nil {
		httphelpers.RespondValidation(c, errs)
		return
	}

	token, err := h.service.ForgotPassword(c.Request.Context(), req.Email)

	if err != nil {
		httphelpers.RespondInternalError(c, err)
		return
	}

	// DEV helper: return reset token in response for local testing only.
	if h.cfg.ExposeResetToken && token != "" {
		httphelpers.RespondOK(c, gin.H{
			"message":     "Se o usuário existir, um link de reset foi enviado.",
			"reset_token": token,
		})
		return
	}

	httphelpers.RespondOK(c, gin.H{"message": "Se o usuário existir, um link de reset foi enviado."})
}

// ResetPassword godoc
// @Summary Finalizar reset de senha
// @Description Recebe o token de reset e a nova senha para atualizar no DB.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Token de reset e nova senha"
// @Success 200 {object} response.Standard
// @Failure 400 {object} response.Standard
// @Failure 500 {object} response.Standard
// @Router /auth/reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}
	if errs := validation.ValidateRequest(req); errs != nil {
		httphelpers.RespondValidation(c, errs)
		return
	}

	if !h.isStrongPassword(req.NewPassword) {
		httphelpers.RespondDomainFail(c, "Senha deve ter no mínimo 8 caracteres, 1 maiúscula, 1 minúscula e 1 especial.")
		return
	}

	err := h.service.ResetPassword(c.Request.Context(), req.Token, req.NewPassword)

	if err != nil {
		httphelpers.RespondDomainFail(c, "Não foi possível redefinir a senha.")
		return
	}

	httphelpers.RespondOK(c, gin.H{"message": "Senha alterada com sucesso."})
}

// RefreshToken godoc
// @Summary Renovar tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "Refresh token"
// @Success 200 {object} response.Standard{data=LoginResponse}
// @Failure 401 {object} response.Standard
// @Failure 500 {object} response.Standard
// @Router /auth/refresh [post]
func (h *Handler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	if req.RefreshToken == "" {
		httphelpers.RespondBindingError(c, errors.New("refresh_token is required"))
		return
	}

	if err := h.checkRateLimitKey(c, "refresh", req.RefreshToken, h.cfg.RefreshRateLimit, h.cfg.RefreshRateWindowSec); err != nil {
		return
	}

	accessToken, refreshToken, userDomain, err := h.service.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		httphelpers.RespondUnauthorized(c, err.Error())
		return
	}

	responseDTO := LoginResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		User:         ToUserResponse(userDomain),
	}

	httphelpers.RespondOK(c, responseDTO)
}

// DeactivateSelf godoc
// @Summary Desativa a própria conta do usuário
// @Description Exige a senha atual para confirmar a intenção e desativa o status do usuário (soft delete).
// @Tags Auth
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param request body DeactivateRequest true "Senha atual do usuário"
// @Success 200 {object} response.Standard
// @Failure 401 {object} response.Standard
// @Failure 400 {object} response.Standard
// @Router /auth/deactivate [post]
func (h *Handler) DeactivateSelf(c *gin.Context) {
	var req DeactivateRequest

	userIDString, exists := middleware.RequireUserID(c)
	if !exists {
		return
	}

	userID, err := uuid.Parse(userIDString)
	if err != nil {
		httphelpers.RespondParamError(c, "user_id", "Invalid user id in token")
		return
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	token, exists := middleware.RequireRawToken(c)
	if !exists {
		return
	}

	err = h.service.DeactivateSelf(
		c.Request.Context(),
		userID,
		req.CurrentPassword,
		token,
	)

	if err != nil {
		if errors.Is(err, auth.ErrInvalidCurrentPassword) {
			httphelpers.RespondDomainFail(c, "Não foi possível desativar a conta.")
			return
		}
		httphelpers.RespondInternalError(c, err)
		return
	}

	httphelpers.RespondOK(c, gin.H{"message": "Account deactivated successfully."})
}

// UpdateUserStatus godoc
// @Summary Atualiza o status de um usuário (Admin-only)
// @Description Permite ao Admin banir, suspender ou reativar um usuário.
// @Tags Admin
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param id path string true "ID do usuário a ser atualizado"
// @Param request body StatusUpdateRequest true "Novo status"
// @Success 200 {object} response.Standard
// @Failure 401 {object} response.Standard
// @Failure 403 {object} response.Standard
// @Router /admin/users/{id}/status [put]
func (h *Handler) UpdateUserStatus(c *gin.Context) {
	var req StatusUpdateRequest

	requesterRole, _ := c.Get("role")
	targetUserID := c.Param("id")

	if user.Role(requesterRole.(string)) != user.RoleAdmin {
		httphelpers.RespondUnauthorized(c, "Acesso negado.")
		return
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		httphelpers.RespondBindingError(c, err)
		return
	}

	userID, err := uuid.Parse(targetUserID)
	if err != nil {
		httphelpers.RespondParamError(c, "id", "ID de usuário inválido na URL")
		return
	}

	err = h.service.UpdateUserStatus(c.Request.Context(), userID, user.Status(req.NewStatus))

	if err != nil {
		httphelpers.RespondInternalError(c, err)
		return
	}

	httphelpers.RespondOK(c, gin.H{"message": fmt.Sprintf("Status do usuário %s alterado para %s.", targetUserID, req.NewStatus)})
}

func (h *Handler) checkRateLimit(c *gin.Context, action string, email string, limit int, windowSec int) error {
	if h.limiter == nil || limit <= 0 || windowSec <= 0 {
		return nil
	}

	ip := c.ClientIP()
	emailKey := strings.ToLower(strings.TrimSpace(email))
	key := fmt.Sprintf("rl:%s:ip:%s:email:%s", action, ip, emailKey)

	allowed, err := h.limiter.Allow(c.Request.Context(), key, limit, time.Duration(windowSec)*time.Second)
	if err != nil {
		httphelpers.RespondInternalError(c, err)
		return err
	}
	if !allowed {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"message": "Muitas tentativas. Tente novamente mais tarde."})
		return errors.New("rate limit exceeded")
	}
	return nil
}

func (h *Handler) checkRateLimitKey(c *gin.Context, action string, rawKey string, limit int, windowSec int) error {
	if h.limiter == nil || limit <= 0 || windowSec <= 0 {
		return nil
	}

	ip := c.ClientIP()
	key := fmt.Sprintf("rl:%s:ip:%s:key:%s", action, ip, hashKey(rawKey))

	allowed, err := h.limiter.Allow(c.Request.Context(), key, limit, time.Duration(windowSec)*time.Second)
	if err != nil {
		httphelpers.RespondInternalError(c, err)
		return err
	}
	if !allowed {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"message": "Muitas tentativas. Tente novamente mais tarde."})
		return errors.New("rate limit exceeded")
	}
	return nil
}

func (h *Handler) isStrongPassword(pw string) bool {
	if len(pw) < 8 {
		return false
	}
	if !h.pwUpper.MatchString(pw) {
		return false
	}
	if !h.pwLower.MatchString(pw) {
		return false
	}
	if !h.pwSymbol.MatchString(pw) {
		return false
	}
	return true
}

func hashKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
