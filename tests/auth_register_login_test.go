package tests

import (
	"AuthGRPC/tests/suite"
	ssoa "github.com/AmirBazanov/protoForAuthGRPC/gen/go/sso"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

const (
	emptyAppId = 0
	appId      = 1
	appSecret  = "test-secret"

	passDefault = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	password := randomFakePassword()
	respReg, err := st.AuthClient.Register(ctx, &ssoa.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, respReg.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssoa.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appId,
	})
	require.NoError(t, err)
	loginTime := time.Now()
	token := respLogin.GetToken()
	require.NotEmpty(t, token)

	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appId, int(claims["appid"].(float64)))
	assert.Equal(t, int(respReg.GetUserId()), int(claims["uid"].(float64)))

	const deltaSeconds = 5
	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTl).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestRegisterLogin_DuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)
	email := gofakeit.Email()
	password := randomFakePassword()
	respReg, err := st.AuthClient.Register(ctx, &ssoa.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetUserId())
	respReg, err = st.AuthClient.Register(ctx, &ssoa.RegisterRequest{
		Email:    email,
		Password: password,
	})
	require.Error(t, err)
	require.Empty(t, respReg.GetUserId())
	assert.Contains(t, err.Error(), "user already exists")

}
func TestRegister_FailCases(t *testing.T) {
	ctx, st := suite.New(t)
	tests := []struct {
		name        string
		email       string
		password    string
		expectedErr string
	}{
		{
			name:        "Registration without pass",
			email:       gofakeit.Email(),
			password:    "",
			expectedErr: "'Password' failed on the 'required'",
		}, {
			name:        "Registration without email",
			email:       "",
			password:    randomFakePassword(),
			expectedErr: "'Email' failed on the 'required'",
		}, {
			name:        "Registration with invalid email",
			email:       strings.Split(gofakeit.Email(), "@")[0],
			password:    randomFakePassword(),
			expectedErr: "'Email' failed on the 'email'",
		}, {
			name:        "Registration with both empty",
			email:       "",
			password:    "",
			expectedErr: "'Email' failed on the 'required'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssoa.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)
	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		expectedErr string
	}{
		{
			name:        "Login with empty password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appId,
			expectedErr: "'Password' failed on the 'required'",
		}, {
			name:        "Login with empty email",
			email:       "",
			appID:       appId,
			password:    randomFakePassword(),
			expectedErr: "'Email' failed on the 'required'",
		}, {
			name:        "Login with invalid email",
			email:       strings.Split(gofakeit.Email(), "@")[0],
			appID:       appId,
			password:    randomFakePassword(),
			expectedErr: "'Email' failed on the 'email'",
		}, {
			name:        "Login with both empty",
			email:       "",
			appID:       appId,
			password:    "",
			expectedErr: "'Email' failed on the 'required'",
		}, {
			name:        "Login with wrong password",
			email:       gofakeit.Email(),
			appID:       appId,
			password:    randomFakePassword(),
			expectedErr: "invalid credentials",
		}, {
			name:        "Login without appId",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       emptyAppId,
			expectedErr: "'AppId' failed on the 'required'",
		}, {
			name:        "Login with invalid appId",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       999,
			expectedErr: "invalid app id",
		},
		{
			name:        "Login with wrong email",
			email:       gofakeit.Email(),
			appID:       appId,
			password:    randomFakePassword(),
			expectedErr: "invalid credentials",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Login with invalid appId" {
				respReg, err := st.AuthClient.Register(ctx, &ssoa.RegisterRequest{
					Email:    tt.email,
					Password: tt.password,
				})
				require.NoError(t, err)
				assert.NotEmpty(t, respReg.GetUserId())
			} else {
				respReg, err := st.AuthClient.Register(ctx, &ssoa.RegisterRequest{
					Email:    gofakeit.Email(),
					Password: randomFakePassword(),
				})
				require.NoError(t, err)
				assert.NotEmpty(t, respReg.GetUserId())
			}
			_, err := st.AuthClient.Login(ctx, &ssoa.LoginRequest{
				Email:    tt.email,
				Password: tt.password,
				AppId:    tt.appID,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, true, passDefault)
}
