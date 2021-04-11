package mailru

import (
	"net/http"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/mailru"
  "github.com/jinzhu/copier"
  
  "github.com/Lunkov/lib-auth/base"
)

type Info struct {
  base.AuthConfig   `yaml:"authconfig"`
 
  OAuthCfg   oauth2.Config
}

func New(cfg *base.AuthConfig) *Info {
  a := &Info{}
  copier.CopyWithOption(a, cfg, copier.Option{IgnoreEmpty: true, DeepCopy: true})
  return a
}

func (a *Info) Init() bool {
  a.OAuthCfg = oauth2.Config{
                RedirectURL:  a.OAuth.Redirect,
                ClientID:     a.OAuth.Client_id,
                ClientSecret: a.OAuth.Secret,
                Endpoint:     mailru.Endpoint,
            }
  a.OAuth.Login_Url = a.OAuthCfg.AuthCodeURL("state", oauth2.AccessTypeOnline)
  return true
}

func (a *Info) AuthUrl() string {
  return a.OAuth.Login_Url
}

func (a *Info) Close() {
}

func (a *Info) Login(login string, password string) (base.User, bool) {
  user := base.User{}
  return user, false
}
  
func (a *Info) OAuthLogin(w http.ResponseWriter, r *http.Request) {
}

func (a *Info) OAuthCallback(w http.ResponseWriter, r *http.Request) {
}

func (a *Info) OAuthGetUserData(code string) ([]byte, error) {
  buf := make([]byte, 0)
  return buf, nil
}

