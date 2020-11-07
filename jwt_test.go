package auth

import (
  "testing"
  "github.com/stretchr/testify/assert"
  
  "net/http"
  
  "github.com/Lunkov/lib-auth/base"
)

func TestCheckJWTServiceGen(t *testing.T) {
  user := base.User{Login: "user1", EMail: "user1@mail"}

  // bad settings
  k1 := JWTItem{ServiceJWTType: "11", ServiceJWTKey: "mkdvrmiot5e8945er89345tmiwr8345rej34n7w46s", ExpiryTime: 100}
  assert.Equal(t, false, k1.JWTInit())
  
  jwtToken, err := k1.JWTGen(&user, "system")
  assert.NotNil(t, err)
  
  // good settings
  k1 = JWTItem{ServiceJWTType: "HS256", ServiceJWTKey: "mkdvrmiot5e8945er89345tmiwr8345rej34n7w46s", ExpiryTime: 100}
  assert.Equal(t, true, k1.JWTInit())

  jwtToken, err = k1.JWTGen(&user, "system")
  assert.Nil(t, err)

  res, _, _ := k1.JWTCheck(jwtToken)

  assert.Equal(t, user.Login, res.Login)
  assert.Equal(t, user.EMail, res.EMail)
}

func TestCheckJWTService(t *testing.T) {
  k1 := JWTItem{ServiceJWTType: "HS256", ServiceJWTKey: "mkdvrmiot5e8945er89345tmiwr8345rej34n7w46s", ExpiryTime: 100}
  assert.Equal(t, true, k1.JWTInit())

  _, httpCode, err := k1.JWTCheck("0000000000")
  assert.NotNil(t, err)
  assert.Equal(t, http.StatusBadRequest, httpCode)
  
  user := base.User{Login: "user1", EMail: "user1@mail"}
  
  jwtToken, err := k1.JWTGen(&user, "system")
  assert.Nil(t, err)

  res, _, err2 := k1.JWTCheck(jwtToken)
  assert.Nil(t, err2)

  assert.Equal(t, "user1", res.Login)
  assert.Equal(t, "user1@mail", res.EMail)
}
