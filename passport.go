package passport

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	AccessTokenExpDuration time.Duration
	AccessTokenSecret      string
}

type Adapter struct {
	config *Config
}

var ErrInvalidToken = errors.New("invalid token")

var ErrParseClaims = errors.New("error when parse claims")

func New(cfg *Config) *Adapter {
	return &Adapter{
		config: cfg,
	}
}

func (a *Adapter) CreateAccessToken(issuer, uid, sid string) (token string, exp time.Time, err error) {

	const op = "adapter.auth.jwt.CreateAccessToken"

	now := time.Now().UTC()

	exp = now.Add(a.config.AccessTokenExpDuration)

	accessClaims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(now),
		Issuer:    issuer,
		ID:        sid,
		Subject:   uid,
	}

	accessTokenObject := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)

	token, err = accessTokenObject.SignedString([]byte(a.config.AccessTokenSecret))

	if err != nil {
		err = fmt.Errorf("%s: %w", op, err)
		exp = time.Time{}
		return "", exp, err
	}

	return token, exp, nil

}

func (a *Adapter) ParseAccessToken(token string, issuer string) (jti string, uid string, err error) {

	const op = "adapter.auth.jwt.ParseAccessToken"

	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	}

	result, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		return []byte(a.config.AccessTokenSecret), nil
	}, opts...)

	if err != nil {
		err = fmt.Errorf("%s: %w: %v", op, ErrParseClaims, err)
		return jti, uid, err
	}

	if !result.Valid {
		err = fmt.Errorf("%s: %w", op, ErrInvalidToken)
		return jti, uid, err
	}

	claims, ok := result.Claims.(*jwt.RegisteredClaims)

	if !ok {
		err = fmt.Errorf("%s: %w", op, ErrParseClaims)
		return jti, uid, err
	}

	if claims.Subject == "" || claims.ID == "" {
		err = fmt.Errorf("%s: %w", op, ErrInvalidToken)
		return "", "", err
	}

	jti, uid = claims.ID, claims.Subject

	return jti, uid, nil
}
