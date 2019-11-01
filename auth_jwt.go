// Package jwt provides Json-Web-Token authentication for the go-json-rest framework
package jwt

import (
	"github.com/ant0ine/go-json-rest/rest"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

// JWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userId is made available as
// request.Env["REMOTE_USER"].(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type JWTMiddleware struct {
	// Realm name to display to the user. Required.
	Realm string

	// Issuer to issued the	JWT.
	Issuer string

	// the subject of the JWT.
	Subject string

	// signing algorithm - possible values are HS256, HS384, HS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// Secret key used for signing. Required.
	Key []byte

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is MaxRefresh + Timeout.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Callback function that should perform the authentication of the user based on userId and
	// password. Must return true on success, false on failure. Required.
	Authenticator func(userId string, password string) bool

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	Authorizator func(userId string, request *rest.Request) bool

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via request.Env["JWT_PAYLOAD"].
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(userId string) map[string]interface{}
}

// MiddlewareFunc makes JWTMiddleware implement the Middleware interface.
func (mw *JWTMiddleware) MiddlewareFunc(handler rest.HandlerFunc) rest.HandlerFunc {

	if mw.Realm == "" {
		log.Fatal("Realm is required")
	}
	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}
	if mw.Key == nil {
		log.Fatal("Key required")
	}
	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}
	if mw.Authenticator == nil {
		log.Fatal("Authenticator is required")
	}
	if mw.Authorizator == nil {
		mw.Authorizator = func(userId string, request *rest.Request) bool {
			return true
		}
	}

	return func(writer rest.ResponseWriter, request *rest.Request) { mw.middlewareImpl(writer, request, handler) }
}

func (mw *JWTMiddleware) middlewareImpl(writer rest.ResponseWriter, request *rest.Request, handler rest.HandlerFunc) {
	claims, payload, err := mw.parseToken(request)

	if err != nil {
		mw.unauthorized(writer)
		return
	}

	err = claims.Validate(jwt.Expected{
		Issuer:  mw.Issuer,
		Subject: mw.Subject,
		Time:    time.Now(),
	})
	if err != nil {
		mw.unauthorized(writer)
		return
	}

	id := claims.ID
	if id == "" {
		mw.unauthorized(writer)
		return
	}

	request.Env["REMOTE_USER"] = id
	request.Env["JWT_PAYLOAD"] = payload

	if !mw.Authorizator(id, request) {
		mw.unauthorized(writer)
		return
	}

	handler(writer, request)
}

// ExtractClaims allows to retrieve the payload
func ExtractClaims(request *rest.Request) map[string]interface{} {
	if request.Env["JWT_PAYLOAD"] == nil {
		emptyClaims := map[string]interface{}{}
		return emptyClaims
	}
	jwtClaims := request.Env["JWT_PAYLOAD"].(map[string]interface{})
	return jwtClaims
}

type resultToken struct {
	Token string `json:"token"`
}

type login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *JWTMiddleware) LoginHandler(writer rest.ResponseWriter, request *rest.Request) {
	loginVals := login{}
	err := request.DecodeJsonPayload(&loginVals)

	if err != nil {
		mw.unauthorized(writer)
		return
	}

	if !mw.Authenticator(loginVals.Username, loginVals.Password) {
		mw.unauthorized(writer)
		return
	}

	signMethod := jose.SignatureAlgorithm(mw.SigningAlgorithm)

	// Create the Claims
	c1 := jwt.Claims{}

	c1.ID = loginVals.Username
	c1.Issuer = mw.Issuer
	c1.Subject = mw.Subject
	c1.Expiry = jwt.NewNumericDate(time.Now().Add(mw.Timeout))

	if mw.MaxRefresh != 0 {
		c1.IssuedAt = jwt.NewNumericDate(time.Now())
	}

	c2 := struct {
		Playload map[string]interface{} `json:"playload"`
	}{}

	if mw.PayloadFunc != nil {
		c2.Playload = make(map[string]interface{})
		for key, value := range mw.PayloadFunc(loginVals.Username) {
			c2.Playload[key] = value
		}
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: signMethod,
			Key:       mw.Key,
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		mw.unauthorized(writer)
		return
	}

	raw, err := jwt.Signed(sig).
		Claims(c1).
		Claims(c2).
		CompactSerialize()

	if err != nil {
		mw.unauthorized(writer)
		return
	}

	_ = writer.WriteJson(resultToken{Token: raw})
}

func (mw *JWTMiddleware) parseToken(request *rest.Request) (*jwt.Claims, map[string]interface{}, error) {
	authHeader := request.Header.Get("Authorization")

	if authHeader == "" {
		return nil, nil, errors.New("Auth header empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return nil, nil, errors.New("Invalid auth header")
	}

	tok, err := jwt.ParseSigned(parts[1])
	if err != nil {
		return nil, nil, err
	}

	var c1 jwt.Claims
	c2 := struct {
		Playload map[string]interface{} `json:"playload"`
	}{}

	err = tok.Claims(mw.Key, &c1, &c2)
	if err != nil {
		return nil, nil, err
	}
	return &c1, c2.Playload, nil
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the JWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *JWTMiddleware) RefreshHandler(writer rest.ResponseWriter, request *rest.Request) {
	c1, playload, err := mw.parseToken(request)

	// Token should be valid anyway as the RefreshHandler is authed
	if err != nil {
		mw.unauthorized(writer)
		return
	}

	err = c1.Validate(jwt.Expected{
		Issuer:  mw.Issuer,
		Subject: mw.Subject,
		Time:    time.Now(),
	})
	if err != nil {
		mw.unauthorized(writer)
		return
	}

	signMethod := jose.SignatureAlgorithm(mw.SigningAlgorithm)

	c1.Expiry = jwt.NewNumericDate(time.Now().Add(mw.Timeout))

	if mw.MaxRefresh != 0 {
		c1.IssuedAt = jwt.NewNumericDate(time.Now())
	}

	c2 := struct {
		Playload map[string]interface{} `json:"playload"`
	}{}

	c2.Playload = playload

	sig, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: signMethod,
			Key:       mw.Key,
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		mw.unauthorized(writer)
		return
	}

	raw, err := jwt.Signed(sig).
		Claims(c1).
		Claims(c2).
		CompactSerialize()

	if err != nil {
		mw.unauthorized(writer)
		return
	}

	_ = writer.WriteJson(resultToken{Token: raw})
}

func (mw *JWTMiddleware) unauthorized(writer rest.ResponseWriter) {
	writer.Header().Set("WWW-Authenticate", "JWT realm="+mw.Realm)
	rest.Error(writer, "Not Authorized", http.StatusUnauthorized)
}
