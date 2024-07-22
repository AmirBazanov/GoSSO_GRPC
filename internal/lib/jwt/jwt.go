package jwt

import (
	"AuthGRPC/internal/domain/models"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

// NewToken TODO: Test
func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":   user.ID,
		"exp":   time.Now().Add(duration).Unix(),
		"appid": app.ID,
		"email": user.Email,
	})
	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
