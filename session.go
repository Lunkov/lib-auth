package auth

import (
  "time"
  "net/http"
  "github.com/golang/glog"
  "github.com/google/uuid"
  
  "github.com/Lunkov/lib-ref"
  "github.com/Lunkov/lib-cache"
  "github.com/Lunkov/lib-auth/base"
)

type DBInfo struct {
  Url              string  `yaml:"url"`
  Max_connections  int     `yaml:"max_connections"`
}

type SessionInfo struct {
  Mode         string         `yaml:"mode"`
  Expiry_time  int64          `yaml:"expiry_time"`
  Redis        DBInfo         `yaml:"redis"`
  Aerospike    DBInfo         `yaml:"aerospike"`
}

type Session struct {
  sessions              cache.ICache
  expiryTimeDuration    time.Duration
  tokenName             string
}

func NewSessions() *Session {
  return &Session{tokenName: "__session"}
}

func (s *Session) HasError() bool {
  if s.sessions == nil {
    return true
  }
  return s.sessions.HasError()
}

func (s *Session) Mode() string {
  if s.sessions == nil {
    return "undefined"
  }
  return s.sessions.GetMode()
}

func (s *Session) Count() int64 {
  if s.sessions == nil {
    return -1
  }
  return s.sessions.Count()
}

func (s *Session) DestroyAll() {
  if s.sessions != nil {
    s.sessions.Clear()
  }
}

func (s *Session) genToken() string {
  uid, _ := uuid.NewUUID()
  sessionToken := uid.String()
  iter := 0
  if s.sessions != nil {
    for iter < 10 {
      ok := s.sessions.Check(sessionToken)
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

func (s *Session) HTTPStart(w http.ResponseWriter, r *http.Request) string {
  var sessionToken string

  reCreate := true
  cookie, err := r.Cookie(s.tokenName)
  if glog.V(9) {
    glog.Infof("LOG: GET COOKIE: '%v' err=%v\n", cookie, err)
  }
  if err == nil && cookie.Value != "" {
    if s.sessions != nil {
      sessionToken = cookie.Value
      _, ok := s.sessions.Get(cookie.Value, &base.User{})
      if ok {
        reCreate = false
      } else {
        s.sessions.Remove(cookie.Value)
      }
    }
  } else {
    if glog.V(2) {
      glog.Warningf("WRN: TOKEN GET COOKIE(%v): '%v'\n", sessionToken, err)
    }
    sessionToken = s.genToken()
    cookie := http.Cookie{Name: s.tokenName, Value: sessionToken, Path: "/", HttpOnly: true}
    http.SetCookie(w, &cookie)
    if glog.V(9) {
      glog.Infof("LOG: SET COOKIE: '%v' cookie=%v\n", sessionToken, cookie)
    }
  }

  if reCreate && s.sessions != nil {
    if glog.V(9) {
      glog.Infof("LOG: TOKEN SET NEW SESSION: '%v'\n", sessionToken)
    }
    s.sessions.Set(sessionToken, base.User{TimeLogin: time.Now()})
  }
  if glog.V(9) {
    glog.Infof("LOG: COOKIE: TOKEN: '%v' = '%v'\n", s.tokenName, sessionToken)
  }
  return sessionToken
}

func (s *Session) SetToken(w http.ResponseWriter, sessionToken string) {
  if glog.V(2) {
    glog.Infof("LOG: COOKIE: SET TOKEN: '%v' = '%v'\n", s.tokenName, sessionToken)
  }
  http.SetCookie(w, &http.Cookie{
    Name:    s.tokenName,
    Value:   sessionToken,
    Path:    "/",
    Expires: time.Now().Add(s.expiryTimeDuration),
  })
}

func (s *Session) GetToken(w http.ResponseWriter, r *http.Request) string {
  c, err := r.Cookie(s.tokenName)
  if err != nil {
    if glog.V(2) {
      glog.Warningf("WRN: COOKIE: GET TOKEN: '%v' = '%v'\n", s.tokenName, err)
    }
    return ""
  }
  if glog.V(2) {
    glog.Infof("LOG: COOKIE: GET TOKEN: '%v' = '%v'\n", s.tokenName, c.Value)
  }
  return c.Value
}

func (s *Session) HTTPUserLogin(w http.ResponseWriter, sessionToken string, user *base.User) {
  user.TimeLogin = time.Now()
  if sessionToken == "" {
    sessionToken = s.genToken()
  }
  if sessionToken != "" {
    if glog.V(9) {
      glog.Infof("LOG: SessionHTTPUserLogin: s.sessions.Set: (token=%v) (user=%v) => %v\n", sessionToken, user, s.expiryTimeDuration)
    }
    s.sessions.Set(sessionToken, *user)
    s.SetToken(w, sessionToken)
  }
}

func (s *Session) HTTPUserLogout(w http.ResponseWriter, sessionToken string) {
  if sessionToken != "" {
    s.sessions.Set(sessionToken, base.User{})
    s.SetToken(w, sessionToken)
  }
}

func (s *Session) Find(sessionToken string) bool {
  return s.sessions.Check(sessionToken)
}

func (s *Session) HTTPCheck(w http.ResponseWriter, r *http.Request) bool {
  sessionToken := s.GetToken(w, r)
  if sessionToken != "" {
    return s.sessions.Check(sessionToken)
  }
  return false
}

func (s *Session) HTTPUserInfo(w http.ResponseWriter, r *http.Request) (*base.User, bool) {
  return s.GetUserInfo(s.GetToken(w, r))
}

func (s *Session) GetUserInfo(sessionToken string) (*base.User, bool) {
  if glog.V(9) {
    glog.Infof("DBG: START: SessionGetUserInfo: (token = %v, s.sessions.DefaultExpiration = %v)", sessionToken, s.expiryTimeDuration)
  }
  if sessionToken != "" {
    var u, user base.User
    u1, ok := s.sessions.Get(sessionToken, &u)
    if glog.V(9) {
      glog.Infof("DBG: SessionGetUserInfo: s.sessions.Get: (%v) %v => %v (%s)", sessionToken, ok, u1, ref.GetType(u1))
    }
    if !ok {
      return nil, false
    }
    ok = false
    if ref.GetType(u1) == "*User" {
      u2, ok := (u1).(*base.User)
      if glog.V(9) {
        glog.Infof("DBG: SessionGetUserInfo: u1.(User): (%v) %v => %v\n", sessionToken, ok, user)
      }
      if !ok {
        return nil, false
      }
      user = *u2
    }
    if ref.GetType(u1) == "User" {
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
func (s *Session) Init(mode string, expiryTime int64, URL string, MaxConnections int) bool {
  if glog.V(9) {
    glog.Infof("DBG: SESSION: Init")
  }
  s.sessions = cache.New(mode, expiryTime, URL, MaxConnections)
  if s.sessions == nil {
    glog.Errorf("ERR: SESSION: Init(%s) error", mode)
    return false
  }
  s.expiryTimeDuration = time.Duration(expiryTime) * time.Second
  glog.Infof("LOG: SESSION: Mode is %s", s.sessions.GetMode())
  return !s.sessions.HasError()
}

func (s *Session) Close() {
  if s.sessions != nil {
    s.sessions.Close()
    s.sessions = nil
  }
}
