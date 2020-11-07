package base

import (
  "time"
  "github.com/golang/glog"
  "github.com/google/uuid"
  "encoding/json"
)

type User struct {
  ID            uuid.UUID       `json:"ID"`
  Login         string          `json:"login"`
  EMail         string          `json:"email"`
  DisplayName   string          `json:"display_name"`
  Avatar        string          `json:"avatar"`
  Language      string          `json:"lang"`
  Group         string          `json:"group"`
  Groups      []string          `json:"groups"`
  TimeLogin     time.Time       `json:"-"`
  AuthCode      string          `json:"-"`
  Disable       bool            `json:"disable"`
}

func (p *User) ToJSON() string {
  b, err := json.Marshal(p)
  if err != nil {
    glog.Errorf("ERR: Person: JSON: %s\n", err)
    return ""
  }
  return string(b)
}

func FromJSON(str string) (*User, error) {
  p := User{}
  if err := json.Unmarshal([]byte(str), &p); err != nil {
    glog.Errorf("ERR: Person: JSON: %s\n", err)
    return nil, err
  }
  return &p, nil
}
