package base

import (
  "testing"
  "github.com/stretchr/testify/assert"
  "github.com/google/uuid"
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

func TestPerson(t *testing.T) {
  var iv User

  uid, _ := uuid.Parse("00000002-0003-0004-0005-000000000001")
  iv = User{ID: uid, Login: "Max", EMail: "max@aaa.ru", Groups: []string{"admin", "superadmin"} }

  assert.Equal(t, uid, iv.ID)
  assert.Equal(t, "Max", iv.Login)
  assert.Equal(t, "max@aaa.ru", iv.EMail)
  assert.Equal(t, []string{"admin", "superadmin"}, iv.Groups)

  iv.Groups = []string{"admin"}

  if !EqualStringArrays(iv.Groups, []string{"admin"}) {
    t.Error(
      "For", "Person Admin",
      "expected", []string{"admin"},
      "got", iv.Groups,
    )
  }

  json_need := `{"ID":"00000002-0003-0004-0005-000000000001","login":"Max","email":"max@aaa.ru","display_name":"","avatar":"","lang":"","group":"","groups":["admin"],"disable":false}`
  json := iv.ToJSON()
  assert.Equal(t, json_need, json)

  iv2, err := FromJSON(json)
  if err != nil {
    t.Error(
      "For", "Person FromJSON ERR",
      "expected", "",
      "got", err.Error(),
    )
  }
  assert.Equal(t, iv.ID, iv2.ID)
  assert.Equal(t, iv.Login, iv2.Login)
  assert.Equal(t, iv.EMail, iv2.EMail)
  assert.Equal(t, iv.Groups, iv2.Groups)

  bad_json := `{"id1":"1111","login":"Max","email":"max@aaa.ru","groups":"admin"}`

  iv3, err2 := FromJSON(bad_json)
  if err2 == nil {
    t.Error(
      "For", "Person FromJSON ERR",
      "expected", "Cannot unmarshal",
      "got", "NULL",
    )
  }
  if iv3 != nil {
    t.Error(
      "For", "Person UUID",
      "expected", "",
      "got", iv2.ID,
    )
  }

}

