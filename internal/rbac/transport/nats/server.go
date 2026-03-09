package nats

import (
	"context"
	"fmt"
	"time"

	"rbac7/internal/rbac/config"
	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/service"

	gonats "github.com/nats-io/nats.go"
)

type Server struct {
	cfg      config.NATSConfig
	service  service.RBACService
	verifier identity.TokenVerifier
}

func NewServer(cfg config.NATSConfig, svc service.RBACService, verifier identity.TokenVerifier) (*Server, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("nats url is required")
	}
	if svc == nil {
		return nil, fmt.Errorf("rbac service is required")
	}
	if verifier == nil {
		return nil, fmt.Errorf("token verifier is required")
	}

	return &Server{cfg: cfg, service: svc, verifier: verifier}, nil
}

func (s *Server) HandleRequest(ctx context.Context, subject string, payload []byte) ([]byte, error) {
	start := time.Now()
	envelope, err := DecodeRequestEnvelope(payload)
	if err != nil {
		return s.encodeErrorResponse("", CodeBadRequest, "invalid request envelope", start), nil
	}

	caller, err := s.verifier.VerifyToken(ctx, envelope.Token)
	if err != nil || caller.UserID == "" {
		return s.encodeErrorResponse(envelope.RequestID, CodeUnauthorized, "unauthorized", start), nil
	}

	ctx = identity.WithCallerContext(ctx, caller)

	switch subject {
	case SubjectCheck:
		return s.handleCheck(ctx, envelope, start)
	case SubjectCheckBatch:
		return s.handleCheckBatch(ctx, envelope, start)
	case SubjectRolesMe:
		return s.handleRolesMe(ctx, envelope, start)
	default:
		return s.encodeErrorResponse(envelope.RequestID, CodeBadRequest, "unsupported subject", start), nil
	}
}

func (s *Server) Register(conn *gonats.Conn) error {
	handlers := map[string]gonats.MsgHandler{
		SubjectCheck: func(msg *gonats.Msg) {
			s.respond(msg, SubjectCheck)
		},
		SubjectCheckBatch: func(msg *gonats.Msg) {
			s.respond(msg, SubjectCheckBatch)
		},
		SubjectRolesMe: func(msg *gonats.Msg) {
			s.respond(msg, SubjectRolesMe)
		},
	}

	for subject, handler := range handlers {
		if _, err := conn.Subscribe(subject, handler); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) respond(msg *gonats.Msg, subject string) {
	if msg == nil {
		return
	}

	response, err := s.HandleRequest(context.Background(), subject, msg.Data)
	if err != nil {
		return
	}
	_ = msg.Respond(response)
}
