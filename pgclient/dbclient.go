package pgclient

import (
  "time"
  "net/http"
  "github.com/google/uuid"
  "github.com/golang/glog"
  "github.com/jinzhu/copier"
  "github.com/jinzhu/gorm"
  "github.com/lib/pq"

  "golang.org/x/crypto/bcrypt"
  
  "github.com/Lunkov/lib-auth/base"
)

type UserAuth struct {
  ID             uuid.UUID     `db:"id"                         json:"id"            yaml:"id"               gorm:"column:id;type:uuid;primary_key;default:uuid_generate_v4()"`
  CreatedAt      time.Time     `db:"created_at;default: now()"  json:"created_at"    sql:"default: now()"    gorm:"type:timestamp with time zone"`
  UpdatedAt      time.Time     `db:"updated_at;default: null"   json:"updated_at"    sql:"default: null"     gorm:"type:timestamp with time zone"`
  DeletedAt     *time.Time     `db:"deleted_at;default: null"   json:"deleted_at"    sql:"default: null"     gorm:"type:timestamp with time zone"`
  
  Login           string        `db:"login"         json:"login"           yaml:"login"    sql:"unique_index:idx_name"`
  EMail           string        `db:"email"         json:"email"           yaml:"email"    sql:"unique_index:idx_email"`
  Mobile          string        `db:"mobile"        json:"mobile"          yaml:"mobile"   sql:"unique_index:idx_mobile"`
  
  Password        string        `db:"pwd"           json:"pwd"             yaml:"pwd"`
  
  Groups          pq.StringArray  `json:"groups"        sql:"column:groups;type:varchar(64)[]"    gorm:"column:groups;type:varchar(64)[]"` // 
  
  Disabled        bool          `db:"disabled"      json:"disabled"        yaml:"disabled"`
}


type Info struct {
  base.AuthConfig     `yaml:"authconfig"`

  Handle       *gorm.DB
}

func (a *Info) Connected() bool {
  return a.Handle != nil
}

func New(cfg *base.AuthConfig) *Info {
  a := &Info{}
  copier.CopyWithOption(a, cfg, copier.Option{IgnoreEmpty: true, DeepCopy: true})
  return a
}

func (a *Info) Init() bool {
  var err error

  a.Handle, err = gorm.Open("postgres", a.DBConnect)
  if err != nil {
    glog.Errorf("ERR: MODELS: failed to connect database (read): %v\n", err)
    return false
  }
  // Get generic database object sql.DB to use its functions
  sqlDB := a.Handle.DB()
  // SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
  sqlDB.SetMaxIdleConns(10)
  // SetMaxOpenConns sets the maximum number of open connections to the database.
  sqlDB.SetMaxOpenConns(100)
  // SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
  sqlDB.SetConnMaxLifetime(time.Hour)
  
  a.Handle.Table(a.AuthTable).AutoMigrate(UserAuth{})
  
  glog.Infof("LOG: DBAuth connected: %v", a.DBConnect)
  return true
}

func (a *Info) Close() {
  if a.Handle != nil {
    a.Handle.Close()
  }
  glog.Infof("LOG: DBAuth disconnected")
}

func (a *Info) Login(login string, password string) (base.User, bool) {
  u := UserAuth{}
  user := base.User{}
  sql1 := a.Handle.Table(a.AuthTable).Where("login = ?", login)
  if sql1 == nil {
    glog.Errorf("ERR: AUTH: Login(%v) not found", login)
    return user, false
  }
  err := sql1.First(&u).Error
  
  if err != nil {
    glog.Errorf("ERR: AUTH: Login(%v) not found", login)
    return user, false
  }
  
  if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
    glog.Errorf("ERR: AUTH: Login(%v) bad password", login)
    return user, false
  }
  user.ID    = u.ID
  user.Login = u.Login
  user.EMail = u.EMail
  user.Groups = u.Groups

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
