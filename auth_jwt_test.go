package jwt

import (
	"testing"
	"time"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	key = []byte("secret key")
)

type DecoderToken struct {
	Token string `json:"token"`
}

func makeTokenString(username string, key []byte) string {

	signMethod := jose.HS256

	// Create the Claims
	c1 := jwt.Claims{}
	c1.ID = username
	c1.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour))
	c1.IssuedAt = jwt.NewNumericDate(time.Now())

	sig, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: signMethod,
			Key:       key,
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return ""
	}

	raw, err := jwt.Signed(sig).
		Claims(c1).
		CompactSerialize()

	if err != nil {
		return ""
	}

	return raw
}

func TestAuthJWT(t *testing.T) {
	// the middleware to test
	authMiddleware := &JWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(userId string, password string) bool {
			return userId == "admin" && password == "admin"
		},
		Authorizator: func(userId string, request *rest.Request) bool {
			return request.Method == "GET"
		},
	}

	// api for testing failure
	apiFailure := rest.NewApi()
	apiFailure.Use(authMiddleware)
	apiFailure.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		t.Error("Should never be executed")
	}))
	handler := apiFailure.MakeHandler()

	// simple request fails
	t.Log("simple request fails")
	recorded := test.RunRequest(t, handler, test.MakeSimpleRequest("GET", "http://localhost/", nil))
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// auth with right cred and wrong method fails
	t.Log("auth with right cred and wrong method fails")
	wrongMethodReq := test.MakeSimpleRequest("POST", "http://localhost/", nil)
	wrongMethodReq.Header.Set("Authorization", "Bearer "+makeTokenString("admin", key))
	recorded = test.RunRequest(t, handler, wrongMethodReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// wrong Auth format - bearer lower case
	t.Log("wrong Auth format - bearer lower case")
	wrongAuthFormat := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	wrongAuthFormat.Header.Set("Authorization", "bearer "+makeTokenString("admin", key))
	recorded = test.RunRequest(t, handler, wrongAuthFormat)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// wrong Auth format - no space after bearer
	t.Log("wrong Auth format - no space after bearer")
	wrongAuthFormat = test.MakeSimpleRequest("GET", "http://localhost/", nil)
	wrongAuthFormat.Header.Set("Authorization", "bearer"+makeTokenString("admin", key))
	recorded = test.RunRequest(t, handler, wrongAuthFormat)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// wrong Auth format - empty auth header
	t.Log("wrong Auth format - empty auth header")
	wrongAuthFormat = test.MakeSimpleRequest("GET", "http://localhost/", nil)
	wrongAuthFormat.Header.Set("Authorization", "")
	recorded = test.RunRequest(t, handler, wrongAuthFormat)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credit, right method but wrong priv key
	t.Log("right credit, right method but wrong priv key")
	wrongPrivKeyReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	wrongPrivKeyReq.Header.Set("Authorization", "Bearer "+makeTokenString("admin", []byte("wrong key")))
	recorded = test.RunRequest(t, handler, wrongPrivKeyReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credit, right method, right priv key but timeout
	t.Log("right credit, right method, right priv key but timeout")
	claims := jwt.Claims{}
	claims.ID = "admin"
	claims.Expiry = jwt.NewNumericDate(time.Unix(0, 0))
	signMethod := jose.HS256
	sig, _ := jose.NewSigner(
		jose.SigningKey{
			Algorithm: signMethod,
			Key:       key,
		},
		(&jose.SignerOptions{}).WithType("JWT"))

	tokenString, _ := jwt.Signed(sig).
		Claims(claims).
		CompactSerialize()

	expiredTimestampReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	expiredTimestampReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, handler, expiredTimestampReq)
	//t.Log(recorded.Recorder.Body.String())
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credit, right method, right priv key but no id
	t.Log("right credit, right method, right priv key but no id")
	claimsNoId := jwt.Claims{}
	claimsNoId.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour))

	tokenNoIdString, _ := jwt.Signed(sig).
		Claims(claimsNoId).
		CompactSerialize()

	noIDReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	noIDReq.Header.Set("Authorization", "Bearer "+tokenNoIdString)
	recorded = test.RunRequest(t, handler, noIDReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// right credit, right method, right priv, wrong signing key on request
	t.Log("right credit, right method, right priv, wrong signing method on request")
	claimsBadSigning := jwt.Claims{}
	claimsBadSigning.ID = "admin"
	claimsBadSigning.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour * 72))

	badKey := []byte("badkey")
	badSig, _ := jose.NewSigner(
		jose.SigningKey{
			Algorithm: signMethod,
			Key:       badKey,
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	tokenBadSigningString, _ := jwt.Signed(badSig).
		Claims(claimsBadSigning).
		CompactSerialize()

	BadSigningReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	BadSigningReq.Header.Set("Authorization", "Bearer "+tokenBadSigningString)
	recorded = test.RunRequest(t, handler, BadSigningReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// api for testing success
	apiSuccess := rest.NewApi()
	apiSuccess.Use(authMiddleware)
	apiSuccess.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		if r.Env["REMOTE_USER"] == nil {
			t.Error("REMOTE_USER is nil")
		}
		user := r.Env["REMOTE_USER"].(string)
		if user != "admin" {
			t.Error("REMOTE_USER is expected to be 'admin'")
		}
		_ = w.WriteJson(map[string]string{"Id": "123"})
	}))

	// auth with right cred and right method succeeds
	t.Log("auth with right cred and right method succeeds")
	validReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	validReq.Header.Set("Authorization", "Bearer "+makeTokenString("admin", key))
	recorded = test.RunRequest(t, apiSuccess.MakeHandler(), validReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	// login tests
	loginApi := rest.NewApi()
	loginApi.SetApp(rest.AppSimple(authMiddleware.LoginHandler))

	// wrong login
	t.Log("wrong login")
	wrongLoginCreds := map[string]string{"username": "admin", "password": "admIn"}
	wrongLoginReq := test.MakeSimpleRequest("POST", "http://localhost/", wrongLoginCreds)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), wrongLoginReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// empty login
	t.Log("empty login")
	emptyLoginCreds := map[string]string{}
	emptyLoginReq := test.MakeSimpleRequest("POST", "http://localhost/", emptyLoginCreds)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), emptyLoginReq)
	recorded.CodeIs(401)
	recorded.ContentTypeIsJson()

	// correct login
	t.Log("correct login")
	before := time.Now().Unix()
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/", loginCreds)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	nToken := DecoderToken{}
	_ = test.DecodeJsonPayload(recorded.Recorder, &nToken)

	newToken, err := jwt.ParseSigned(nToken.Token)
	if err != nil {
		t.Errorf("Received new token with wrong signature:%v", err)
	}

	var newClaims jwt.Claims
	err = newToken.Claims(key, &newClaims)
	if err != nil {
		t.Errorf("newToken claims cant cover to mapclaims")
	}

	if newClaims.ID != "admin" ||
		newClaims.Expiry.Time().Unix() < before {
		t.Errorf("Received new token with wrong data")
	}

	refreshApi := rest.NewApi()
	refreshApi.Use(authMiddleware)
	refreshApi.SetApp(rest.AppSimple(authMiddleware.RefreshHandler))

	// refresh with expired max refresh
	t.Logf("refresh with expired max refresh")
	unRefreshableClaims := jwt.Claims{}
	unRefreshableClaims.ID = "admin"
	// the combination actually doesn't make sense but is ok for the test
	unRefreshableClaims.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour))
	unRefreshableClaims.IssuedAt = jwt.NewNumericDate(time.Unix(0, 0))
	tokenString, _ = jwt.Signed(sig).
		Claims(unRefreshableClaims).
		CompactSerialize()

	unRefreshableReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	unRefreshableReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, refreshApi.MakeHandler(), unRefreshableReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	// valid refresh
	t.Log("valid refresh")
	refreshableClaims := jwt.Claims{}
	refreshableClaims.ID = "admin"
	// we need to substract one to test the case where token is being created in
	// the same second as it is checked -> < wouldn't fail
	refreshableClaims.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour))
	refreshableClaims.IssuedAt = jwt.NewNumericDate(time.Now())
	tokenString, _ = jwt.Signed(sig).
		Claims(refreshableClaims).
		CompactSerialize()

	validRefreshReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	validRefreshReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, refreshApi.MakeHandler(), validRefreshReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	rToken := DecoderToken{}
	_ = test.DecodeJsonPayload(recorded.Recorder, &rToken)
	refreshToken, err := jwt.ParseSigned(rToken.Token)

	if err != nil || refreshToken == nil {
		t.Errorf("Received refreshed token with wrong signature:%v", err)
		return
	}
	var refreshClaims jwt.Claims
	err = refreshToken.Claims(key, &refreshClaims)
	if err != nil {
		t.Errorf("refreshToken claims cant cover to map claims")
		return
	}

	if refreshClaims.ID != "admin" ||
		!refreshClaims.IssuedAt.Time().Equal(refreshableClaims.IssuedAt.Time()) ||
		refreshClaims.Expiry.Time().Before(refreshableClaims.Expiry.Time()) {
		t.Errorf("Received refreshed token with wrong data")
	}
}

func TestAuthJWTPayload(t *testing.T) {
	authMiddleware := &JWTMiddleware{
		Realm:            "test zone",
		SigningAlgorithm: "HS256",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		Authenticator: func(userId string, password string) bool {
			return userId == "admin" && password == "admin"
		},
		PayloadFunc: func(userId string) map[string]interface{} {
			// tests normal value
			// tests overwriting of reserved jwt values should have no effect
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
	}

	loginApi := rest.NewApi()
	loginApi.SetApp(rest.AppSimple(authMiddleware.LoginHandler))

	// correct payload
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/", loginCreds)
	recorded := test.RunRequest(t, loginApi.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	nToken := DecoderToken{}
	_ = test.DecodeJsonPayload(recorded.Recorder, &nToken)
	newToken, err := jwt.ParseSigned(nToken.Token)

	if err != nil {
		t.Errorf("Received new token with wrong signature:%v", err)
	}
	var newClaims jwt.Claims
	c2 := struct {
		Playload map[string]interface{} `json:"playload"`
	}{}

	err = newToken.Claims(key, &newClaims, &c2)
	if err != nil {
		t.Errorf("newToken claims cant cover to map claims")
	}

	if c2.Playload["testkey"].(string) != "testval" || newClaims.Expiry.Time().Equal(time.Unix(0, 0)) {
		t.Errorf("Received new token without payload")
	}

	// correct payload after refresh
	refreshApi := rest.NewApi()
	refreshApi.Use(authMiddleware)
	refreshApi.SetApp(rest.AppSimple(authMiddleware.RefreshHandler))

	refreshableClaims := jwt.Claims{}
	refreshableClaims.ID = "admin"
	refreshableClaims.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour))
	refreshableClaims.IssuedAt = jwt.NewNumericDate(time.Now())

	c2.Playload = make(map[string]interface{})
	c2.Playload["testkey"] = "testval"

	signMethod := jose.HS256
	sig, _ := jose.NewSigner(
		jose.SigningKey{
			Algorithm: signMethod,
			Key:       key,
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	tokenString, _ := jwt.Signed(sig).
		Claims(refreshableClaims).
		Claims(c2).
		CompactSerialize()

	validRefreshReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	validRefreshReq.Header.Set("Authorization", "Bearer "+tokenString)
	recorded = test.RunRequest(t, refreshApi.MakeHandler(), validRefreshReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	rToken := DecoderToken{}
	_ = test.DecodeJsonPayload(recorded.Recorder, &rToken)
	refreshToken, err := jwt.ParseSigned(rToken.Token)

	if err != nil {
		t.Errorf("Received refreshed token with wrong signature:%v", err)
	}

	var refreshClaims jwt.Claims

	err = refreshToken.Claims(key, &refreshClaims, &c2)
	if err != nil {
		t.Errorf("refreshToken claims cant cover to map claims")
	}

	if c2.Playload["testkey"].(string) != "testval" {
		t.Errorf("Received new token without payload")
	}

	// payload is accessible in request
	payloadApi := rest.NewApi()
	payloadApi.Use(authMiddleware)
	payloadApi.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		testval := r.Env["JWT_PAYLOAD"].(map[string]interface{})["testkey"].(string)
		_ = w.WriteJson(map[string]string{"testkey": testval})
	}))

	payloadClaims := jwt.Claims{}
	payloadClaims.ID = "admin"
	payloadClaims.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour))
	payloadClaims.IssuedAt = jwt.NewNumericDate(time.Now())
	c2.Playload = make(map[string]interface{})
	c2.Playload["testkey"] = "testval"
	payloadTokenString, _ := jwt.Signed(sig).
		Claims(payloadClaims).
		Claims(c2).
		CompactSerialize()

	payloadReq := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	payloadReq.Header.Set("Authorization", "Bearer "+payloadTokenString)
	recorded = test.RunRequest(t, payloadApi.MakeHandler(), payloadReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	payload := map[string]string{}
	_ = test.DecodeJsonPayload(recorded.Recorder, &payload)

	if payload["testkey"] != "testval" {
		t.Errorf("Received new token without payload")
	}

}

func TestClaimsDuringAuthorization(t *testing.T) {
	authMiddleware := &JWTMiddleware{
		Realm:            "test zone",
		SigningAlgorithm: "HS256",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		PayloadFunc: func(userId string) map[string]interface{} {
			// Set custom claim, to be checked in Authorizator method
			return map[string]interface{}{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(userId string, password string) bool {
			// Not testing authentication, just authorization, so always return true
			return true
		},
		Authorizator: func(userId string, request *rest.Request) bool {
			jwt_claims := ExtractClaims(request)

			// Check the actual claim, set in PayloadFunc
			return (jwt_claims["testkey"] == "testval")
		},
	}

	// Simple endpoint
	endpoint := func(w rest.ResponseWriter, r *rest.Request) {
		// Dummy endpoint, output doesn't really matter, we are checking
		// the code returned
		_ = w.WriteJson(map[string]string{"Id": "123"})
	}

	// Setup simple app structure
	loginApi := rest.NewApi()
	loginApi.SetApp(rest.AppSimple(authMiddleware.LoginHandler))
	loginApi.Use(&rest.IfMiddleware{
		// Only authenticate non /login requests
		Condition: func(request *rest.Request) bool {
			return request.URL.Path != "/login"
		},
		IfTrue: authMiddleware,
	})
	api_router, _ := rest.MakeRouter(
		rest.Post("/login", authMiddleware.LoginHandler),
		rest.Get("/", endpoint),
	)
	loginApi.SetApp(api_router)

	// Authenticate
	loginCreds := map[string]string{"username": "admin", "password": "admin"}
	rightCredReq := test.MakeSimpleRequest("POST", "http://localhost/login", loginCreds)
	recorded := test.RunRequest(t, loginApi.MakeHandler(), rightCredReq)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()

	// Decode received token, to be sent with endpoint request
	nToken := DecoderToken{}
	_ = test.DecodeJsonPayload(recorded.Recorder, &nToken)

	// Request endpoint, triggering Authorization.
	// If we get a 200 then the claims were available in Authorizator method
	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	req.Header.Set("Authorization", "Bearer "+nToken.Token)
	recorded = test.RunRequest(t, loginApi.MakeHandler(), req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
}
