package openldap

import (
  "testing"
  "strconv"
  "github.com/stretchr/testify/assert"
  "flag"
  "github.com/google/uuid"
  "github.com/golang/glog"
  
  "github.com/Lunkov/lib-auth/base"
)

func EqualStringArrays(a, b []string) bool {
    if len(a) != len(b) {
        return false
    }
    for i, v := range a {
        if v != b[i] {
            return false
        }
    }
    return true
}

func TestLDAPUUID(t *testing.T) {
  uid, _ := uuid.Parse("3c572bf3-9429-5160-ae8b-b9f9d2a197f0")
  str := "12312Login"
  id := uuid.NewSHA1(uuid.Nil, ([]byte)(str))
  assert.Equal(t, id, uid)

}

func TestLDAP(t *testing.T) {
  flag.Set("alsologtostderr", "true")
  flag.Set("log_dir", ".")
  flag.Set("v", "9")
  flag.Parse()

  glog.Info("Logging configured")

  var user base.User
  var ok bool
  cfg := base.AuthConfig{ CODE: "ldap1", TypeAuth: "openldap",
                           LDAP: base.LDAPInfo{ Host: "localhost",
                                Port: 389,
                                Ldap_bind_user: "cn=admin,dc=test,dc=dig,dc=center",
                                Ldap_bind_pwd: "password",
                                Ldap_base_dn: "dc=test,dc=dig,dc=center",
                                Ldap_filter_user: "(&(objectClass=organizationalPerson)(uid=%s))", 
                                //Ldap_filter_user: "(&(objectClass=person)(uid=%s))",
                                //Ldap_filter_user: "(&(objectClass=organizationalPerson)(uid=%s))",
                                Ldap_filter_group: "(memberUid=%s)"}}
  ldap := New(&cfg)
  res := ldap.Init()
  assert.Equal(t, true, res)
  assert.Equal(t, true, ldap.Connected())

  user, ok = ldap.Login("admin", "password")
  // assert.Equal(t, true, ok)

  assert.Equal(t, uuid.Nil, user.ID)
  assert.Equal(t, "", user.Login)
  assert.Equal(t, "", user.EMail)
  // assert.Equal(t, []string{}, user.Groups)

  user_id := "17362ff6-e15a-52d2-a3b1-bec4251a9b7d"
  user, ok = ldap.Login("u.user", "123123123")

  assert.Equal(t, true, ok)
  assert.Equal(t, user_id, user.ID.String())
  assert.Equal(t, "u.user", user.Login)
  assert.Equal(t, "u.user@test.dig.center", user.EMail)
  assert.Equal(t, []string{"Users", "NewsMakers"}, user.Groups)

  user, ok = ldap.Login("u.user", "123123123")

  assert.Equal(t, true, ok)
  assert.Equal(t, user_id, user.ID.String())
  assert.Equal(t, "u.user", user.Login)
  assert.Equal(t, "u.user@test.dig.center", user.EMail)
  assert.Equal(t, []string{"Users", "NewsMakers"}, user.Groups)

  user, ok = ldap.Login("u.user", "123123123")

  assert.Equal(t, true, ok)
  assert.Equal(t, user_id, user.ID.String())
  assert.Equal(t, "u.user", user.Login)
  assert.Equal(t, "u.user@test.dig.center", user.EMail)
  assert.Equal(t, []string{"Users", "NewsMakers"}, user.Groups)

  defer ldap.Close()

}

// Run It
// go test -bench=. -benchmem -run BenchmarkLDAP ./...
// go test -bench=. -benchmem -benchtime=1s -run BenchmarkLDAP ./..

func BenchmarkLDAP(b *testing.B) {
	flag.Set("alsologtostderr", "true")
	flag.Set("log_dir", ".")
	flag.Set("v", "0")
	flag.Parse()
    
  var user base.User
  var ok bool
  cfg := base.AuthConfig{ CODE: "ldap1", TypeAuth: "openldap",
                           LDAP: base.LDAPInfo{ Host: "localhost",
                                Port: 389,
                                Ldap_bind_user: "cn=admin,dc=test,dc=dig,dc=center",
                                Ldap_bind_pwd: "password",
                                Ldap_base_dn: "dc=test,dc=dig,dc=center",
                                Ldap_filter_user: "(&(objectClass=organizationalPerson)(uid=%s))",
                                Ldap_filter_group: "(memberUid=%s)"}}

  ldap := New(&cfg)
  res := ldap.Init()
  
  assert.Equal(b, true, res)
  assert.Equal(b, true, ldap.Connected())

  b.ResetTimer()
  for i := 1; i <= 8; i *= 2 {
		b.Run(strconv.Itoa(i), func(b *testing.B) {
			b.SetParallelism(i)
      b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
          user, ok = ldap.Login("u.user", "123123123")
          assert.Equal(b, true, ok)
          assert.Equal(b, "u.user", user.Login)
        }
      })
    })
  }
 
  defer ldap.Close()
}
