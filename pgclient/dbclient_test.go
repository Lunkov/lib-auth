package pgclient

import (
  "testing"
  "strconv"
  "github.com/stretchr/testify/assert"
  "flag"
  "github.com/google/uuid"
  "github.com/golang/glog"
  
  "github.com/Lunkov/lib-auth/base"
)

func TestDB(t *testing.T) {
  flag.Set("alsologtostderr", "true")
  flag.Set("log_dir", ".")
  flag.Set("v", "9")
  flag.Parse()

  glog.Info("Logging configured")

  var user base.User
  var ok bool
  cfg := base.AuthConfig{ CODE: "db", TypeAuth: "postgres",
                                   DBConnect: "host=localhost port=14345 user=dbuser dbname=testdb password=password sslmode=disable",
                                   AuthTable: "auth_user",           
                                }

  db := New(&cfg)
  assert.Equal(t, true, db.Init())
  assert.Equal(t, true, db.Connected())

  user, ok = db.Login("admin", "password")
  // assert.Equal(t, true, ok)

  assert.Equal(t, uuid.Nil, user.ID)
  assert.Equal(t, "", user.Login)
  assert.Equal(t, "", user.EMail)
  // assert.Equal(t, []string{}, user.Groups)

  user_id := "86d19863-cd4f-484f-b8b7-44fc5f38616a"

  // hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
  // glog.Errorf("password: %v", string(hash))
  // PWD: $2a$10$NT4WdWXFyO5QZnDaN.skCex9WQFyoI3gLYgBUc8YfKEiafe5b/qEO
  user, ok = db.Login("u.user", "123123123")

  assert.Equal(t, true, ok)
  assert.Equal(t, user_id, user.ID.String())
  assert.Equal(t, "u.user", user.Login)
  assert.Equal(t, "u.user@test.dig.center", user.EMail)
  assert.Equal(t, []string{"Users"}, user.Groups)

  user, ok = db.Login("u.user", "123123123")

  assert.Equal(t, true, ok)
  assert.Equal(t, user_id, user.ID.String())
  assert.Equal(t, "u.user", user.Login)
  assert.Equal(t, "u.user@test.dig.center", user.EMail)
  assert.Equal(t, []string{"Users"}, user.Groups)

  user, ok = db.Login("u.user", "123123123")

  assert.Equal(t, true, ok)
  assert.Equal(t, user_id, user.ID.String())
  assert.Equal(t, "u.user", user.Login)
  assert.Equal(t, "u.user@test.dig.center", user.EMail)
  assert.Equal(t, []string{"Users"}, user.Groups)

  defer db.Close()

}

// Run It
// go test -bench=. -benchmem -run BenchmarkLDAP ./...
// go test -bench=. -benchmem -benchtime=1s -run BenchmarkLDAP ./..

func BenchmarkDBClient(b *testing.B) {
	flag.Set("alsologtostderr", "true")
	flag.Set("log_dir", ".")
	flag.Set("v", "0")
	flag.Parse()
    
  var user base.User
  var ok bool
  cfg := base.AuthConfig{ CODE: "db", TypeAuth: "postgres",
                                   DBConnect: "host=localhost port=14345 user=dbuser dbname=testdb password=password sslmode=disable",
                                   AuthTable: "auth_user",           
                                }

  db := New(&cfg)
  
  res := db.Init()
  assert.Equal(b, true, res)
  assert.Equal(b, true, db.Connected())

  b.ResetTimer()
  for i := 1; i <= 8; i *= 2 {
		b.Run(strconv.Itoa(i), func(b *testing.B) {
			b.SetParallelism(i)
      b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
          user, ok = db.Login("u.user", "123123123")
          assert.Equal(b, true, ok)
          assert.Equal(b, "u.user", user.Login)
        }
      })
    })
  }
 
  defer db.Close()
}

