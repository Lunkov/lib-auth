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

var memAuth = make(map[string]AuthInterface)
var hasOAuth = false

//////////////////////////////////////////////////
// Array Class Implementation
///
func Count() int {
  return len(memAuth)
}

func HasOAuth() bool {
  return hasOAuth
}

func New(code string, info base.AuthLoadInfo, filename string, fileBuf []byte) {
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
      t := mapAuth[code]
      in = &t
      break
    default:
      glog.Infof("ERR: AUTH: Auth type (%s): '%s'", info.Type(), code, info.DisplayName)
      break
  }
  if in != nil {
    ok = in.Init()
    if ok {
      memAuth[code] = in
    }
  }
}

func Get(code string) *AuthInterface {
  i, ok := memAuth[code]
  if ok {
    return &i
  }
  return nil
}

func Close() {
  for _, info := range memAuth {
    info.Close()
  }
}

func GetListPwd() *map[string]map[string]string {
  res := make(map[string]map[string]string)
  for key, item := range memAuth {
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

func GetListOAuth() *map[string]map[string]string {
  res := make(map[string]map[string]string)
  for key, item := range memAuth {
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

func ToJSONPwd() string {
  cnt := 0
  res := ""
  for key, item := range memAuth {
    if item.Enabled() && item.Type() == "openldap" {
      res += fmt.Sprintf(`{"code": "%s", "type": "%s", "display_name": "%s", "image": "%s"}`, key, item.Type(), item.Name(), item.Img())
      cnt ++
    }
  }
  return fmt.Sprintf(`{"count": %d, "data":{ %s }}`, cnt, res)
}

func ToJSONOAuth() string {
  cnt := 0
  res := ""
  for key, item := range memAuth {
    if item.Enabled() && item.Type() != "openldap" {
      res += fmt.Sprintf(`{"code": "%s", "type": "%s", "display_name": "%s", "image": "%s"}`, key, item.Type(), item.Name(), item.Img())
      cnt ++
    }
  }
  return fmt.Sprintf(`{"count": %d, "data":{ %s }}`, cnt, res)
}

func AuthUser(code string, params *map[string]string) (base.User, bool) {
  ok := false
  user := base.User{}
  mod := Get(code)
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

func LoadYAML(filename string, fileBuf []byte) int {
  var err error
  var mapAuth = make(map[string]base.AuthLoadInfo)

  err = yaml.Unmarshal(fileBuf, mapAuth)
  if err != nil {
    glog.Fatalf("ERR: yamlFile(%s): YAML: %v", filename, err)
  }
  if(len(mapAuth) > 0) {
    for key, item := range mapAuth {
      if !item.Disabled {
        New(key, item, filename, fileBuf)
      }
    }
  }

  return len(mapAuth)
}
