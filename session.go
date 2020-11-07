package auth

import (
  "time"
  "net/http"
  "github.com/golang/glog"
  "github.com/google/uuid"
  
  "github.com/Lunkov/lib-cache"
  "github.com/Lunkov/lib-auth/base"
)

type RedisInfo struct {
  Url              string  `yaml:"url"`
  Max_connections  int     `yaml:"max_connections"`
}

type SessionInfo struct {
  Mode         string         `yaml:"mode"`
  Expiry_time  int64          `yaml:"expiry_time"`
  Redis        RedisInfo      `yaml:"redis"`
}

var sessionCache *cache.Cache = nil
const session_token string = "__session"

func SessionHasError() bool {
  if sessionCache == nil {
    return true
  }
  return sessionCache.HasError()
}

func SessionMode() string {
  if sessionCache == nil {
    return "undefined"
  }
  return sessionCache.Mode()
}

func SessionCount() int64 {
  if sessionCache == nil {
    return -1
  }
  return sessionCache.Count()
}

func SessionDestroyAll() {
  if sessionCache != nil {
    sessionCache.Clear()
  }
}

func genToken() string {
  uid, _ := uuid.NewUUID()
  sessionToken := uid.String()
  iter := 0
  if sessionCache != nil {
    for iter < 10 {
      ok := sessionCache.Check(sessionToken)
      if !ok {
        break
      }
      uid, _ := uuid.NewUUID()
      sessionToken = uid.String()
      iter++
    }
  }    
  if glog.V(9) {
    glog.Infof("DBG: GENERATE TOKEN: %s\n", sessionToken)
  }
  return sessionToken
}

func SessionHTTPStart(w http.ResponseWriter, r *http.Request) string {
  var sessionToken string

  reCreate := true
  cookie, err := r.Cookie(session_token)
  if glog.V(9) {
    glog.Infof("LOG: GET COOKIE: '%v' err=%v\n", cookie, err)
  }
  if err == nil && cookie.Value != "" {
    if sessionCache != nil {
      sessionToken = cookie.Value
      _, ok := sessionCache.Get(cookie.Value, &base.User{})
      if ok {
        reCreate = false
      } else {
        sessionCache.Remove(cookie.Value)
      }
    }
  } else {
    if glog.V(2) {
      glog.Warningf("WRN: TOKEN GET COOKIE(%v): '%v'\n", sessionToken, err)
    }
    sessionToken = genToken()
    cookie := http.Cookie{Name: session_token, Value: sessionToken, Path: "/", HttpOnly: true}
    http.SetCookie(w, &cookie)
    if glog.V(9) {
      glog.Infof("LOG: SET COOKIE: '%v' cookie=%v\n", sessionToken, cookie)
    }
  }

  if reCreate && sessionCache != nil {
    if glog.V(9) {
      glog.Infof("LOG: TOKEN SET NEW SESSION: '%v'\n", sessionToken)
    }
    sessionCache.Set(sessionToken, base.User{TimeLogin: time.Now()})
  }
  if glog.V(9) {
    glog.Infof("LOG: COOKIE: TOKEN: '%v' = '%v'\n", session_token, sessionToken)
  }
  return sessionToken
}

func SetToken(w http.ResponseWriter, sessionToken string) {
  if glog.V(2) {
    glog.Infof("LOG: COOKIE: SET TOKEN: '%v' = '%v'\n", session_token, sessionToken)
  }
  http.SetCookie(w, &http.Cookie{
    Name:    session_token,
    Value:   sessionToken,
    Expires: time.Now().Add(time.Duration(sessionCache.DefaultExpiration()) * time.Second),
  })
}

func GetToken(w http.ResponseWriter, r *http.Request) string {
  c, err := r.Cookie(session_token)
  if err != nil {
    if glog.V(2) {
      glog.Warningf("WRN: COOKIE: GET TOKEN: '%v' = '%v'\n", session_token, err)
    }
    return ""
  }
  if glog.V(2) {
    glog.Infof("LOG: COOKIE: GET TOKEN: '%v' = '%v'\n", session_token, c.Value)
  }
  return c.Value
}

func SessionHTTPUserLogin(w http.ResponseWriter, sessionToken string, user *base.User) {
  user.TimeLogin = time.Now()
  if sessionToken == "" {
    sessionToken = genToken()
  }
  if sessionToken != "" {
    if glog.V(9) {
      glog.Infof("LOG: SessionHTTPUserLogin: sessionCache.Set: (token=%v) (user=%v) => %v\n", sessionToken, user, sessionCache.DefaultExpiration())
    }
    sessionCache.Set(sessionToken, *user)
    setToken(w, sessionToken)
  }
}

func SessionHTTPUserLogout(w http.ResponseWriter, sessionToken string) {
  if sessionToken != "" {
    sessionCache.Set(sessionToken, base.User{})
    setToken(w, sessionToken)
  }
}

func SessionFind(sessionToken string) bool {
  return sessionCache.Check(sessionToken)
}

func SessionHTTPCheck(w http.ResponseWriter, r *http.Request) bool {
  sessionToken := getToken(w, r)
  if sessionToken != "" {
    return sessionCache.Check(sessionToken)
  }
  return false
}

func SessionHTTPUserInfo(w http.ResponseWriter, r *http.Request) (*base.User, bool) {
  return SessionGetUserInfo(getToken(w, r))
}

func SessionGetUserInfo(sessionToken string) (*base.User, bool) {
  if glog.V(9) {
    glog.Infof("DBG: START: SessionGetUserInfo: (token = %v, sessionCache.DefaultExpiration = %v)", sessionToken, sessionCache.DefaultExpiration())
  }
  if sessionToken != "" {
    var u, user base.User
    u1, ok := sessionCache.Get(sessionToken, &u)
    if glog.V(9) {
      glog.Infof("DBG: SessionGetUserInfo: sessionCache.Get: (%v) %v => %v (%s)", sessionToken, ok, u1, sessionCache.GetType(u1))
    }
    if !ok {
      return nil, false
    }
    ok = false
    if sessionCache.GetType(u1) == "*User" {
      u2, ok := (u1).(*base.User)
      if glog.V(9) {
        glog.Infof("DBG: SessionGetUserInfo: u1.(User): (%v) %v => %v\n", sessionToken, ok, user)
      }
      if !ok {
        return nil, false
      }
      user = *u2
    }
    if sessionCache.GetType(u1) == "User" {
      u2, ok := (u1).(base.User)
      if !ok {
        if glog.V(9) {
          glog.Errorf("ERR: SessionGetUserInfo: u1.(User): (%v) %v => %v\n", sessionToken, ok, user)
        }
        return nil, false
      }
      user = u2
    }
    if user.EMail == "" {
      if glog.V(9) {
        glog.Warningf("WRN: SessionGetUserInfo: user.EMail == EMPTY: (%v) %v => %v\n", sessionToken, ok, user)
      }
      return nil, false
    }
    return &user, true
  }
  return nil, false
}


////
// Init
////
func SessionInit(mode string, expiryTime int64, redisURL string, redisMaxConnections int) bool {
  if glog.V(9) {
    glog.Infof("DBG: SESSION: Init")
  }
  sessionCache = cache.New(mode, expiryTime, redisURL, redisMaxConnections)
  if sessionCache == nil {
    glog.Errorf("ERR: SESSION: Init(%s) error\n", mode)
    return false
  }
  glog.Infof("LOG: SESSION: Mode is %s\n", sessionCache.Mode())
  return !sessionCache.HasError()
}

func SessionClose() {
  if sessionCache != nil {
    sessionCache.Close()
    sessionCache = nil
  }
}
