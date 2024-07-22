package auth

import (
	"AuthGRPC/internal/services/auth"
	"context"
	"errors"
	ssoa "github.com/AmirBazanov/protoForAuthGRPC/gen/go/sso"
	"github.com/go-playground/validator/v10"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(ctx context.Context, email string, password string, appID int32) (token string, err error)
	Register(ctx context.Context, email string, password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error)
}

type serverAPI struct {
	validator *validator.Validate
	ssoa.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	validate := validator.New()
	server := &serverAPI{
		validator: validate,
		auth:      auth,
	}
	ssoa.RegisterAuthServer(gRPC, server)
}

func (s *serverAPI) Login(ctx context.Context, req *ssoa.LoginRequest) (*ssoa.LoginResponse, error) {
	if err := s.validateGrpc(req); err != nil {
		return nil, err
	}
	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if errors.Is(err, auth.ErrInvalidAppId) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, "Internal Server Error")
	}
	return &ssoa.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssoa.RegisterRequest) (*ssoa.RegisterResponse, error) {
	if err := s.validateGrpc(req); err != nil {
		return nil, err
	}
	userID, err := s.auth.Register(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.Internal, "Internal Server Error")
	}
	return &ssoa.RegisterResponse{UserId: userID}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssoa.IsAdminRequest) (*ssoa.IsAdminResponse, error) {
	if err := s.validateGrpc(req); err != nil {
		return nil, err
	}
	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, "Internal Server Error")
	}
	return &ssoa.IsAdminResponse{IsAdmin: isAdmin}, nil
}

func (s *serverAPI) validateGrpc(req interface{}) error {
	if err := s.validator.Struct(req); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}
