package auth

import (
  "testing"
  "github.com/stretchr/testify/assert"

  "flag"
  
  "github.com/golang/glog"
  "github.com/google/uuid"
  
  "github.com/Lunkov/lib-env"
  "github.com/Lunkov/lib-auth/base"
)

func TestAuth(t *testing.T) {
  flag.Set("alsologtostderr", "true")
  flag.Set("log_dir", ".")
  flag.Set("v", "9")
  flag.Parse()

  glog.Info("Logging configured")
  
  var code string = "test.dig.center"
  var iv base.User
  var ok bool
  
  a := New()
  
  env.LoadFromFiles("./etc.test/auth", ".yaml", a.Load)

  var params = map[string]string{
                            "login": "admin",
                            "password": "password"}

  assert.Equal(t, 3, a.Count())
  assert.Equal(t, true, a.HasOAuth())

  tjs_need := "{\"count\": 1, \"data\":{ {\"code\": \"test.dig.center\", \"type\": \"openldap\", \"display_name\": \"test.dig.center\", \"image\": \"\"} }}"
  tjs := a.ToJSONPwd()
  assert.Equal(t, tjs_need, tjs)

  tjs_need = "{\"count\": 1, \"data\":{ {\"code\": \"mail.ru\", \"type\": \"mailru\", \"display_name\": \"mail.ru\", \"image\": \"mail-ru.png\"} }}"
  tjs = a.ToJSONOAuth()
  assert.Equal(t, tjs_need, tjs)
  
  // ldap1_get_need := AuthModInfo(AuthModInfo{Name:"Corp_OpenLDAP", Type:"openldap"})
  ldap1_get := a.Get("ldap1")
  assert.Nil(t, ldap1_get)

  ldap1_get = a.Get(code)
  assert.NotNil(t, ldap1_get)
  if ldap1_get != nil {
    assert.Equal(t, "openldap", (*ldap1_get).Type())
  }
  
  auth_all_need := map[string]map[string]string{"test.dig.center":map[string]string{"code":"test.dig.center", "display_name":"test.dig.center", "image":"", "type":"openldap"}}
  auth_all := a.GetListPwd()
  assert.Equal(t, &auth_all_need, auth_all)

  auth_all_need = map[string]map[string]string{"mail.ru":map[string]string{"code":"mail.ru", "display_name":"mail.ru", "image":"mail-ru.png", "type":"mailru", "url":"https://o2.mail.ru/login?access_type=online&client_id=11111&redirect_uri=https%3A%2F%2Fauth.digitaleconomy.space%2Foauth%2Fmailru%2Fcallback&response_type=code&state=state"}}
  auth_all = a.GetListOAuth()
  assert.Equal(t, &auth_all_need, auth_all)
  
  iv, ok = a.AuthUser(code, &params)

  assert.Equal(t, false, ok)
  assert.Equal(t, uuid.Nil, iv.ID)
  assert.Equal(t, "", iv.Login)
  assert.Equal(t, "", iv.EMail)
  var ar_empty_string []string
  assert.Equal(t, ar_empty_string, iv.Groups)

  user_id := "17362ff6-e15a-52d2-a3b1-bec4251a9b7d"
  var params2 = map[string]string{
                            "login": "u.user",
                            "password": "123123123"}

  iv, ok = a.AuthUser(code, &params2)
  
  assert.Equal(t, true, ok)
  assert.Equal(t, user_id, iv.ID.String())
  assert.Equal(t, "u.user", iv.Login)
  assert.Equal(t, "u.user@test.dig.center", iv.EMail)
  assert.Equal(t, []string{"Users"}, iv.Groups)
  
  defer a.Close() 
}
