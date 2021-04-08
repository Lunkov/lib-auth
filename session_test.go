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
  s := NewSessions()
  s.Init("map", 1000, "", 100)
  res := s.Mode()
  assert.Equal(t, "map", res)
  
  s.Close()
}

func TestEMailUUID(t *testing.T) {
  uid, _ := uuid.Parse("abbf4958-17d9-56e3-afe4-30f21ebd1513")
  str := "login123123@mail.ru"
  id := uuid.NewSHA1(uuid.Nil, ([]byte)(str))
  assert.Equal(t, id, uid)
}

func TestLoadMem(t *testing.T) {
  var info base.User
  
  s := NewSessions()
  assert.Equal(t, true, s.HasError())
  assert.Equal(t, "undefined", s.Mode())
  assert.Equal(t, int64(-1), s.Count())
  
  s.Close()
  
  s.Init("map", 1000, "", 100)
  assert.Equal(t, false, s.HasError())
  assert.Equal(t, "map", s.Mode())
  assert.Equal(t, int64(0), s.Count())

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
  
  s := NewSessions()
  okInit := s.Init("redis", 0, "redis://localhost:6379/0", 10)
  assert.Equal(t, true, okInit)

  s.DestroyAll()
  
  res := s.Mode()
  assert.Equal(t, "redis", res)
  assert.Equal(t, int64(0), s.Count())
  
  assert.Equal(t, false, s.Find("1111"))

  s.Close()
}

func TestHTTPMemory(t *testing.T) {
	flag.Parse()
  
  s := NewSessions()
  s.Init("map", 10000, "", 100)
  s.DestroyAll()
  res := s.Mode()
  assert.Equal(t, "map", res)
  assert.Equal(t, int64(0), s.Count())

  uid, _ := uuid.Parse("00000002-0003-0004-0005-000000000001")
  info := base.User{ID: uid, Login: "Max", EMail: "max@aaa.ru", Groups: []string{""} }
  
  req, err := http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)

  rr := httptest.NewRecorder()
  
  token_begin := s.HTTPStart(rr, req)
  assert.NotEqual(t, "", token_begin)
  assert.Equal(t, int64(1), s.Count())

  request := &http.Request{Header: http.Header{"Cookie": rr.HeaderMap["Set-Cookie"]}}
  cookie, err := request.Cookie("__session")
  assert.Nil(t, err)
  
  //handler := http.HandlerFunc(SessionHTTPUserInfo)
  user, ok := s.HTTPUserInfo(rr, req)
  // Extract the dropped cookie from the request.
  assert.Equal(t, false, ok)
  assert.Nil(t, user)

  req, err = http.NewRequest("GET", "/api/v1/login", nil)
  assert.Nil(t, err)
  
  req.AddCookie(cookie)

  //  LOGIN
  rr = httptest.NewRecorder()
  token := s.GetToken(rr, req)
  
  assert.Equal(t, token_begin, token)

  s.HTTPUserLogin(rr, token, &info)
  assert.Equal(t, int64(1), s.Count())

  req, err = http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)
  
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()
  user, ok = s.HTTPUserInfo(rr, req)
  glog.Infof("LOG: MEM: SessionHTTPUserInfo: (user = %v)\n", user)
  
  assert.Equal(t, true, ok)
  assert.Equal(t, info.Login, user.Login)
  assert.Equal(t, info.EMail, user.EMail)

  req, err = http.NewRequest("GET", "/api/v1/logout", nil)

  assert.Nil(t, err)

  req.AddCookie(cookie)

  rr = httptest.NewRecorder()

  token = s.GetToken(rr, req)
  
  assert.Equal(t, token_begin, token)

  s.HTTPUserLogout(rr, token)

  req, err = http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)
  
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()
  user, ok = s.HTTPUserInfo(rr, req)

  assert.Equal(t, false, ok)
  assert.Nil(t, user)

  s.Close()
}

func TestHTTPRedis(t *testing.T) {
  s := NewSessions()
  s.Init("redis", 0, "redis://localhost:6379/0", 100)
  s.DestroyAll()
  res := s.Mode()
  assert.Equal(t, "redis", res)
  assert.Equal(t, int64(0), s.Count())

  uid, _ := uuid.Parse("00000002-0003-0004-0005-000000000001")
  info := base.User{ID: uid, Login: "Max", EMail: "max@aaa.ru", Groups: []string{""} }
  
  req, err := http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)

  rr := httptest.NewRecorder()
  
  token_begin := s.HTTPStart(rr, req)

  assert.NotEqual(t, "", token_begin)
  assert.Equal(t, int64(1), s.Count())

  request := &http.Request{Header: http.Header{"Cookie": rr.HeaderMap["Set-Cookie"]}}
  cookie, err := request.Cookie("__session")
  assert.Nil(t, err)
  
  user, ok := s.HTTPUserInfo(rr, req)
  // Extract the dropped cookie from the request.

  assert.Equal(t, false, ok)
  assert.Nil(t, user)

  req, err = http.NewRequest("GET", "/api/v1/login", nil)
  assert.Nil(t, err)
  
  req.AddCookie(cookie)

  //  LOGIN
  rr = httptest.NewRecorder()
  token := s.GetToken(rr, req)
  
  assert.Equal(t, token_begin, token)

  glog.Infof("LOG: SessionHTTPUserLogin: (user = %v)\n", info)
  s.HTTPUserLogin(rr, token, &info)

  assert.Equal(t, int64(1), s.Count())

  req, err = http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()
  user, ok = s.HTTPUserInfo(rr, req)
  glog.Infof("LOG: SessionHTTPUserInfo: (user = %v)\n", user)
  assert.Equal(t, true, ok)
  assert.NotNil(t, user)

  req, err = http.NewRequest("GET", "/api/v1/logout", nil)
  assert.Nil(t, err)
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()

  token = s.GetToken(rr, req)
  assert.Equal(t, token_begin, token)
  glog.Infof("LOG: SessionHTTPUserLogout: (token = %v)\n", token)
  s.HTTPUserLogout(rr, token)

  req, err = http.NewRequest("GET", "/api/v1/iam", nil)
  assert.Nil(t, err)
  req.AddCookie(cookie)

  rr = httptest.NewRecorder()
  user, ok = s.HTTPUserInfo(rr, req)
  glog.Infof("LOG: SessionHTTPUserInfo after SessionHTTPUserLogout: (token = %v)\n", token)
  assert.Equal(t, false, ok)

  assert.Nil(t, user)

  s.Close()
}
