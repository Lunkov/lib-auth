package openldap

import (
  "io"
  "fmt"
  "crypto/sha1"
  "sync"
  "net/http"
  "github.com/go-ldap/ldap/v3"
  "github.com/google/uuid"
  "github.com/golang/glog"
  "github.com/jinzhu/copier"
  
  "github.com/Lunkov/lib-auth/base"
)

type Info struct {
  base.AuthConfig     `yaml:"authconfig"`

  LdapConn       *ldap.Conn // Connect for Admin User
  LdapConnUser   *ldap.Conn // Check user password
  MUU            sync.RWMutex
  MUA            sync.RWMutex
}

func (a *Info) Connected() bool {
  return a.LdapConn != nil && a.LdapConnUser != nil
}

func New(cfg *base.AuthConfig) *Info {
  a := &Info{}
  copier.CopyWithOption(a, cfg, copier.Option{IgnoreEmpty: true, DeepCopy: true})
  return a
}

func (a *Info) Init() bool {
  var err error
  str_conn := fmt.Sprintf("%s:%d", a.LDAP.Host, a.LDAP.Port)
  // User connect
  a.LdapConnUser, err = ldap.Dial("tcp", str_conn)
  if err != nil {
    glog.Errorf("ERR: LDAP (%s): %s\n", str_conn, err)
    return false
  }
  // Admin Connect and Bind
  a.LdapConn, err = ldap.Dial("tcp", str_conn)
  if err != nil {
    glog.Errorf("ERR: LDAP (%s): %s\n", str_conn, err)
    return false
  }
  err = a.LdapConn.Bind(a.LDAP.Ldap_bind_user, a.LDAP.Ldap_bind_pwd)
  if err != nil {
    glog.Errorf("ERR: LDAP BIND (%s): %s\n", a.LDAP.Ldap_bind_user, err)
    return false
  }
  glog.Infof("LOG: LDAP %s connected\n", str_conn)
  return true
}

func (a *Info) Close() {
  if a.LdapConnUser != nil {
    a.LdapConnUser.Close()
  }
  if a.LdapConn != nil {
    a.LdapConn.Close()
  }
  str_conn := fmt.Sprintf("%s:%d", a.LDAP.Host, a.LDAP.Port)
  glog.Infof("LOG: LDAP %s disconnected\n", str_conn)
}

func (a *Info) Login(login string, password string) (base.User, bool) {
  user := base.User{}
  if a.LdapConn == nil || a.LdapConnUser == nil {
    str_conn := fmt.Sprintf("%s:%d", a.LDAP.Host, a.LDAP.Port)
    glog.Errorf("ERR: AUTH: LOGIN: LDAP NOT CONNECTED (%s, admin=%v, user=%v)\n", str_conn, a.LdapConn, a.LdapConnUser)
    return user, false
  }
  
  // Search for the given username
  str_filter := fmt.Sprintf(a.LDAP.Ldap_filter_user, login)
  searchRequest := ldap.NewSearchRequest(
      a.LDAP.Ldap_base_dn,
      ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
      str_filter,
      []string{"dn", "mail", "giveName", "uid", "cn"},
      nil,
  )

  a.MUA.RLock()
  if glog.V(9) {
    glog.Infof("DBG: LDAP SearchRequest (%s)\n", str_filter)
  }
  sr, err := a.LdapConn.Search(searchRequest)
  a.MUA.RUnlock()
  if err != nil {
    glog.Errorf("ERR: LDAP SEARCH (%s): %s\n", str_filter, err)
    return user, false
  }

  if len(sr.Entries) != 1 {
    glog.Errorf("ERR: LDAP SEARCH: User does not exist or too many entries returned (result = %d)", len(sr.Entries))
    return user, false
  }

  userdn := sr.Entries[0].DN
  email := sr.Entries[0].GetAttributeValue("mail")

  groups, err := a.getGroupsOfUser(login)
  if err != nil {
    glog.Errorf("ERR: LDAP: Error getting groups for user %s: %+v", login, err)
  }
  if glog.V(9) {
    glog.Infof("LOG: LDAP: User '%s' has Groups: %+v", login, groups)
  }

  // Bind as the user to verify their password
  a.MUU.Lock()
  err = a.LdapConnUser.Bind(userdn, password)
  a.MUU.Unlock()
  if err != nil {
    glog.Errorf("ERR: LDAP BIND (%s): %s\n", userdn, err)
    return user, false
  }
  if glog.V(9) {
    glog.Infof("LOG: LDAP: User dn found: %s", userdn)
  }

  h := sha1.New()
  io.WriteString(h, login)
  loginHash := fmt.Sprintf("%x", h.Sum(nil))
  user.ID    = uuid.NewSHA1(uuid.Nil, ([]byte)(loginHash))
  user.Login = login
  user.EMail = email
  user.Groups = groups

  return user, true
}
  
func (a *Info) OAuthLogin(w http.ResponseWriter, r *http.Request) {
}

func (a *Info) OAuthCallback(w http.ResponseWriter, r *http.Request) {
}

func (a *Info) OAuthGetUserData(code string) ([]byte, error) {
  buf := make([]byte, 0)
  return buf, nil
}

// GetGroupsOfUser returns the group for a user.
func (a *Info) getGroupsOfUser(username string) ([]string, error) {
  str_filter := fmt.Sprintf(a.LDAP.Ldap_filter_group, username)
  searchRequest := ldap.NewSearchRequest(
    a.LDAP.Ldap_base_dn,
    ldap.ScopeWholeSubtree,
    ldap.NeverDerefAliases,
    0,
    0,
    false,
    str_filter,
    []string{"cn"}, // can it be something else than "cn"?
    nil,
  )
  a.MUA.RLock()
  if glog.V(9) {
    glog.Infof("DBG: LDAP SearchRequest (%s)\n", str_filter)
  }
  sr, err := a.LdapConn.Search(searchRequest)
  a.MUA.RUnlock()
  if err != nil {
    glog.Errorf("ERR: LDAP SEARCH (%s): %s\n", str_filter, err)
    return nil, err
  }
  groups := []string{}
  for _, entry := range sr.Entries {
    groups = append(groups, entry.GetAttributeValue("cn"))
  }
  return groups, nil
}
