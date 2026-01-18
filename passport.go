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

var ErrInvalidToken = errors.New("invalid token")

var ErrParseClaims = errors.New("error when parse claims")

type CreateParms struct {
	Issuer          string
	UID             string
	SID             string
	Secret          string
	ExpiresDuration time.Duration
}

func CreateAccessToken(params CreateParms) (token string, exp time.Time, err error) {

	const op = "adapter.auth.jwt.CreateAccessToken"

	now := time.Now().UTC()

	exp = now.Add(params.ExpiresDuration)

	accessClaims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(now),
		Issuer:    params.Issuer,
		ID:        params.SID,
		Subject:   params.UID,
	}

	accessTokenObject := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)

	token, err = accessTokenObject.SignedString([]byte(params.Secret))

	if err != nil {
		err = fmt.Errorf("%s: %w", op, err)
		exp = time.Time{}
		return "", exp, err
	}

	return token, exp, nil

}

type VerifyParams struct {
	Token  string
	Issuer string
	Secret string
}

func ParseAccessToken(params VerifyParams) (jti string, uid string, err error) {

	const op = "adapter.auth.jwt.ParseAccessToken"

	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(params.Issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	}

	result, err := jwt.ParseWithClaims(params.Token, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		return []byte(params.Secret), nil
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
