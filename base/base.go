package base

type OAuthInfo struct {
  Login_Url               string    `yaml:"login_url"`
  Logout_Url              string    `yaml:"logout_url"`
  Client_id               string    `yaml:"client_id"`
  Redirect                string    `yaml:"redirect"`
  Secret                  string    `yaml:"secret"`
}

type LDAPInfo struct {
  Host                    string    `yaml:"host"`
  Port                    int       `yaml:"port"`

  Ldap_attr_id            string    `yaml:"attr_id"`
  Ldap_attr_first_name    string    `yaml:"attr_first_name"`
  Ldap_attr_last_name     string    `yaml:"attr_last_name"`
  Ldap_attr_email         string    `yaml:"attr_email"`

  Ldap_class_group        string    `yaml:"class_group"`

  Ldap_base_dn            string    `yaml:"base_dn"`
  Ldap_bind_user          string    `yaml:"bind_user"`
  Ldap_bind_pwd           string    `yaml:"bind_pwd"`

  Ldap_filter_user        string    `yaml:"filter_user"`
  Ldap_filter_group       string    `yaml:"filter_group"`
}

type AuthConfig struct {
  CODE                    string    `yaml:"code"`
  TypeAuth                string    `yaml:"type"`
  DisplayName             string    `yaml:"display_name"`
  Image                   string    `yaml:"image"`
  Disabled                bool      `yaml:"disabled"`
  
  LDAP                    LDAPInfo  `yaml:"ldap"`
  OAuth                   OAuthInfo `yaml:"oauth"`

  Check_groups            string    `yaml:"check_groups"`
}

type AuthLoadInfo struct {
  AuthConfig  `yaml:"authconfig"`
}

//////////////////////////////////////////////////
// Base Class Implementation
///
func (a *AuthConfig) Type() string {
  return a.TypeAuth
}

func (a *AuthConfig) Name() string {
  return a.DisplayName
}

func (a *AuthConfig) Img() string {
  return a.Image
}

func (a *AuthConfig) Enabled() bool {
  return !a.Disabled
}

func (a *AuthConfig) Connected() bool {
  return false
}

func (a *AuthConfig) AuthUrl() string {
  return ""
}
