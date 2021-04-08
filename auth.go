package auth

import (
  "fmt"
  "time"
  "net/http"
  "gopkg.in/yaml.v2"
  "github.com/golang/glog"
  
  "github.com/Lunkov/lib-auth/base"
  "github.com/Lunkov/lib-auth/openldap"
)

type AuthInterface interface {
  Init() bool
  Close()
  
  Type() string
  Name() string
  Img() string
  
  AuthUrl() string
  
  Connected() bool
  Enabled() bool
  
  Login(login string, password string) (base.User, bool)
  
  OAuthLogin(w http.ResponseWriter, r *http.Request)
  OAuthCallback(w http.ResponseWriter, r *http.Request)
  OAuthGetUserData(code string) ([]byte, error)
}

type Auth struct {
  ai          map[string]AuthInterface
  hasOAuth    bool
}

func New() (*Auth) {
  return &Auth{ai: make(map[string]AuthInterface), hasOAuth: false}
}

//////////////////////////////////////////////////
// Array Class Implementation
///
func (a *Auth) Count() int {
  return len(a.ai)
}

func (a *Auth) HasOAuth() bool {
  return a.hasOAuth
}

func (a *Auth) Add(code string, info base.AuthLoadInfo, filename string, fileBuf []byte) {
  var err error
  var ok bool
  var in AuthInterface
  if glog.V(2) {
    glog.Infof("LOG: AUTH: Append(%s): '%s'", code, info.DisplayName)
  }
  switch info.Type() {
    case "openldap":
      var mapAuth = make(map[string]openldap.Info)
      err = yaml.Unmarshal(fileBuf, mapAuth)
      if err != nil {
        glog.Fatalf("ERR: OPENLDAP: yamlFile(%s): YAML: %v", filename, err)
      }
      t := a.ai[code]
      in = t
      break
    default:
      glog.Infof("ERR: AUTH: Auth type (%s): code='%s' name='%s'", info.Type(), code, info.DisplayName)
      break
  }
  if in != nil {
    ok = in.Init()
    if ok {
      a.ai[code] = in
    }
  }
}

func (a *Auth) Get(code string) *AuthInterface {
  i, ok := a.ai[code]
  if ok {
    return &i
  }
  return nil
}

func (a *Auth) Close() {
  for _, info := range a.ai {
    info.Close()
  }
}

func (a *Auth) GetListPwd() *map[string]map[string]string {
  res := make(map[string]map[string]string)
  for key, item := range a.ai {
    if item.Enabled() && item.Type() == "openldap" {
      res[key] = make(map[string]string)
      res[key]["code"] = key
      res[key]["type"] = item.Type()
      res[key]["display_name"] = item.Name()
      res[key]["image"] = item.Img()
    }
  }
  return &res
}

func (a *Auth) GetListOAuth() *map[string]map[string]string {
  res := make(map[string]map[string]string)
  for key, item := range a.ai {
    if item.Enabled() && item.Type() != "openldap" {
      res[key] = make(map[string]string)
      res[key]["code"] = key
      res[key]["type"] = item.Type()
      res[key]["display_name"] = item.Name()
      res[key]["image"] = item.Img()
      res[key]["url"] = item.AuthUrl()
    }
  }
  return &res
}

func (a *Auth) ToJSONPwd() string {
  cnt := 0
  res := ""
  for key, item := range a.ai {
    if item.Enabled() && item.Type() == "openldap" {
      res += fmt.Sprintf(`{"code": "%s", "type": "%s", "display_name": "%s", "image": "%s"}`, key, item.Type(), item.Name(), item.Img())
      cnt ++
    }
  }
  return fmt.Sprintf(`{"count": %d, "data":{ %s }}`, cnt, res)
}

func (a *Auth) ToJSONOAuth() string {
  cnt := 0
  res := ""
  for key, item := range a.ai {
    if item.Enabled() && item.Type() != "openldap" {
      res += fmt.Sprintf(`{"code": "%s", "type": "%s", "display_name": "%s", "image": "%s"}`, key, item.Type(), item.Name(), item.Img())
      cnt ++
    }
  }
  return fmt.Sprintf(`{"count": %d, "data":{ %s }}`, cnt, res)
}

func (a *Auth) AuthUser(code string, params *map[string]string) (base.User, bool) {
  ok := false
  user := base.User{}
  mod := a.Get(code)
  if mod == nil {
	  glog.Errorf("ERR: AuthUser(): Code(%s) not found", code)
	  return user, false
  }
  switch (*mod).Type() {
    case "openldap":
      if (*mod).Connected() {
        user, ok = (*mod).Login((*params)["login"], (*params)["password"])
      }
      break
    default:
      glog.Errorf("ERR: AuthUser(%s)", code)
      break;
  }
  if !ok {
    user.AuthCode  = code
    user.TimeLogin = time.Now()
  }
  return user, ok
}

func (a *Auth) Load(filename string, fileBuf []byte) int {
  var err error
  var mapAuth = make(map[string]base.AuthLoadInfo)

  err = yaml.Unmarshal(fileBuf, mapAuth)
  if err != nil {
    glog.Fatalf("ERR: yamlFile(%s): YAML: %v", filename, err)
  }
  if(len(mapAuth) > 0) {
    for key, item := range mapAuth {
      if item.Enabled() {
        a.Add(key, item, filename, fileBuf)
      }
    }
  }

  return len(mapAuth)
}
