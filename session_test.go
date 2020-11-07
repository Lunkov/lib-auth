package auth

import (
  "testing"
  "github.com/stretchr/testify/assert"

  "flag"
  "github.com/golang/glog"
  "github.com/google/uuid"
  "net/http"
  "net/http/httptest"
  
  "github.com/Lunkov/lib-auth/base"
)

func TestCheckEnv(t *testing.T) {
  SessionInit("memory", 1000, "", 100)
  res := SessionMode()
  assert.Equal(t, "memory", res)
  
  SessionClose()
}

func TestEMailUUID(t *testing.T) {
  uid, _ := uuid.Parse("abbf4958-17d9-56e3-afe4-30f21ebd1513")
  str := "login123123@mail.ru"
  id := uuid.NewSHA1(uuid.Nil, ([]byte)(str))
  assert.Equal(t, id, uid)
}

func TestLoadMem(t *testing.T) {
  var info base.User
  
  assert.Equal(t, true, SessionHasError())
  assert.Equal(t, "undefined", SessionMode())
  assert.Equal(t, int64(-1), SessionCount())
  
  SessionClose()
  
  SessionInit("memory", 1000, "", 100)
  assert.Equal(t, false, SessionHasError())
  assert.Equal(t, "memory", SessionMode())
  assert.Equal(t, int64(0), SessionCount())

  uid, _ := uuid.Parse("00000002-0003-0004-0005-000000000001")
  info = base.User{ID: uid, Login: "Max", EMail: "max@aaa.ru", Groups: []string{""} }

  var testCache = map[string]base.User{}
  assert.Equal(t, 0, len(testCache))
  
  testCache["123"] = info
  assert.Equal(t, 1, len(testCache))
}

func TestLoadRedis(t *testing.T) {
  flag.Set("alsologtostderr", "true")
  flag.Set("log_dir", ".")
  flag.Set("v", "9")
  flag.Parse()

  glog.Info("Logging configured")
  
  okInit := SessionInit("redis", 0, "redis://localhost:6379/0", 10)
  assert.Equal(t, true, okInit)

  SessionDestroyAll()
  
  res := SessionMode()
  assert.Equal(t, "redis", res)
  assert.Equal(t, int64(0), SessionCount())
  
  assert.Equal(t, false, SessionFind("1111"))

  SessionClose()
}

func TestHTTPMemory(t *testing.T) {
	flag.Parse()
  
  SessionInit("memory", 10000, "", 100)
  SessionDestroyAll()
  res := SessionMode()
  assert.Equal(t, "memory", res)
  assert.Equal(t, int64(0), SessionCount())

  uid, _ := uuid.Parse("00000002-0003-0004-0005-000000000001")
  info := base.User{ID: uid, Login: "Max", EMail: "max@aaa.ru", Groups: []string{""} }
  
  req, err := http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)

  rr := httptest.NewRecorder()
  
  token_begin := SessionHTTPStart(rr, req)
  assert.NotEqual(t, "", token_begin)
  assert.Equal(t, int64(1), SessionCount())

  request := &http.Request{Header: http.Header{"Cookie": rr.HeaderMap["Set-Cookie"]}}
  cookie, err := request.Cookie("__session")
  assert.Nil(t, err)
  
  //handler := http.HandlerFunc(SessionHTTPUserInfo)
  user, ok := SessionHTTPUserInfo(rr, req)
  // Extract the dropped cookie from the request.
  assert.Equal(t, false, ok)
  assert.Nil(t, user)

  req, err = http.NewRequest("GET", "/api/v1/login", nil)
  assert.Nil(t, err)
  
  req.AddCookie(cookie)

  //  LOGIN
  rr = httptest.NewRecorder()
  token := getToken(rr, req)
  
  assert.Equal(t, token_begin, token)

  SessionHTTPUserLogin(rr, token, &info)
  assert.Equal(t, int64(1), SessionCount())

  req, err = http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)
  
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()
  user, ok = SessionHTTPUserInfo(rr, req)
  glog.Infof("LOG: MEM: SessionHTTPUserInfo: (user = %v)\n", user)
  
  assert.Equal(t, true, ok)
  assert.Equal(t, info.Login, user.Login)
  assert.Equal(t, info.EMail, user.EMail)

  req, err = http.NewRequest("GET", "/api/v1/logout", nil)

  assert.Nil(t, err)

  req.AddCookie(cookie)

  rr = httptest.NewRecorder()

  token = getToken(rr, req)
  
  assert.Equal(t, token_begin, token)

  SessionHTTPUserLogout(rr, token)

  req, err = http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)
  
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()
  user, ok = SessionHTTPUserInfo(rr, req)

  assert.Equal(t, false, ok)
  assert.Nil(t, user)

  SessionClose()
}

func TestHTTPRedis(t *testing.T) {
  SessionInit("redis", 0, "redis://localhost:6379/0", 100)
  SessionDestroyAll()
  res := SessionMode()
  assert.Equal(t, "redis", res)
  assert.Equal(t, int64(0), SessionCount())

  uid, _ := uuid.Parse("00000002-0003-0004-0005-000000000001")
  info := base.User{ID: uid, Login: "Max", EMail: "max@aaa.ru", Groups: []string{""} }
  
  req, err := http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)

  rr := httptest.NewRecorder()
  
  token_begin := SessionHTTPStart(rr, req)

  assert.NotEqual(t, "", token_begin)
  assert.Equal(t, int64(1), SessionCount())

  request := &http.Request{Header: http.Header{"Cookie": rr.HeaderMap["Set-Cookie"]}}
  cookie, err := request.Cookie("__session")
  assert.Nil(t, err)
  
  user, ok := SessionHTTPUserInfo(rr, req)
  // Extract the dropped cookie from the request.

  assert.Equal(t, false, ok)
  assert.Nil(t, user)

  req, err = http.NewRequest("GET", "/api/v1/login", nil)
  assert.Nil(t, err)
  
  req.AddCookie(cookie)

  //  LOGIN
  rr = httptest.NewRecorder()
  token := getToken(rr, req)
  
  assert.Equal(t, token_begin, token)

  glog.Infof("LOG: SessionHTTPUserLogin: (user = %v)\n", info)
  SessionHTTPUserLogin(rr, token, &info)

  assert.Equal(t, int64(1), SessionCount())

  req, err = http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()
  user, ok = SessionHTTPUserInfo(rr, req)
  glog.Infof("LOG: SessionHTTPUserInfo: (user = %v)\n", user)
  assert.Equal(t, true, ok)
  assert.NotNil(t, user)

  req, err = http.NewRequest("GET", "/api/v1/logout", nil)
  assert.Nil(t, err)
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()

  token = getToken(rr, req)
  assert.Equal(t, token_begin, token)
  glog.Infof("LOG: SessionHTTPUserLogout: (token = %v)\n", token)
  SessionHTTPUserLogout(rr, token)

  req, err = http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()
  user, ok = SessionHTTPUserInfo(rr, req)
  glog.Infof("LOG: SessionHTTPUserInfo after SessionHTTPUserLogout: (token = %v)\n", token)
  assert.Equal(t, false, ok)

  assert.Nil(t, user)

  SessionClose()
}
