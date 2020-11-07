package auth

import (
  "errors"
  "time"
  "net/http"
  "github.com/google/uuid"
  "github.com/golang/glog"
  "github.com/dgrijalva/jwt-go"
  
  "github.com/Lunkov/lib-auth/base"
)

type JWTItem struct {
  ServiceJWTKey   string          `yaml:"jwt_key"       json:"-"`
  ServiceJWTType  string          `yaml:"jwt_type"`
  ExpiryTime      time.Duration   `yaml:"expiry_time"`
  useHMAC         bool
  signRSA         *jwt.SigningMethodRSA
  signHMAC        *jwt.SigningMethodHMAC
}

type Credentials struct {
  password  string   `json:"password"`
  login     string   `json:"login"`
}

type Claims struct {
  ID              string    `json:"uid"`
  Login           string    `json:"login"`
  EMail           string    `json:"email"`
  Avatar          string    `json:"avatar"`
  DisplayName     string    `json:"displayname"`
  Group           string    `json:"group"`
  Groups        []string    `json:"groups"`
  jwt.StandardClaims
}

func (c *JWTItem) JWTInit() bool {
  c.signHMAC = nil
  c.signRSA = nil
  if c.ServiceJWTType == "HS256" {
    c.signHMAC = jwt.SigningMethodHS256
    c.useHMAC = true
  }
  if c.ServiceJWTType == "HS384" {
    c.signHMAC = jwt.SigningMethodHS384
    c.useHMAC = true
  }
  if c.ServiceJWTType == "HS512" {
    c.signHMAC = jwt.SigningMethodHS512
    c.useHMAC = true
  }
  if c.ServiceJWTType == "RS256" {
    c.signRSA = jwt.SigningMethodRS256
    c.useHMAC = false
  }
  if c.ServiceJWTType == "RS384" {
    c.signRSA = jwt.SigningMethodRS384
    c.useHMAC = false
  }
  if c.ServiceJWTType == "RS512" {
    c.signRSA = jwt.SigningMethodRS512
    c.useHMAC = false
  }
  return (c.signRSA != nil && !c.useHMAC) || (c.signHMAC != nil && c.useHMAC)
}

func (c *JWTItem) JWTGen(user *base.User, issuer string) (string, error) {
  var err error
  tokenString := ""
  
  expirationTime := time.Now().Add(c.ExpiryTime * time.Second)
  
  // Create the JWT claims, which includes the username and expiry time
  claims := &Claims{
    ID:          user.ID.String(),
    Login:       user.Login,
    EMail:       user.EMail,
    DisplayName: user.DisplayName,
    Avatar:      user.Avatar,
    Group:       user.Group,
    Groups:      user.Groups,
    StandardClaims: jwt.StandardClaims{
      // In JWT, the expiry time is expressed as unix milliseconds
      ExpiresAt: expirationTime.Unix(),
      Issuer:    issuer,
    },
  }

  if c.useHMAC {
    if c.signHMAC == nil {
      glog.Errorf("ERR: JWT: Undefined Type Sign '%s'\n", c.ServiceJWTType)
      return tokenString, errors.New("ERR: JWT: Undefined Type Sign")
    }
    token := jwt.NewWithClaims(c.signHMAC, claims)
    // Create the JWT string
    if len(c.ServiceJWTKey) > 0 {
      tokenString, err = token.SignedString([]byte(c.ServiceJWTKey))
      if err != nil {
        glog.Errorf("ERR: JWT: SignedString: %v\n", err)
        return tokenString, err
      }
    }
  } else {
    if c.signRSA == nil {
      glog.Errorf("ERR: JWT: Undefined Type Sign '%s'\n", c.ServiceJWTType)
      return tokenString, errors.New("ERR: JWT: Undefined Type Sign")
    }
    token := jwt.NewWithClaims(c.signRSA, claims)
    // Create the JWT string
    if len(c.ServiceJWTKey) > 0 {
      tokenString, err = token.SignedString([]byte(c.ServiceJWTKey))
      if err != nil {
        glog.Errorf("ERR: JWT: SignedString: %v\n", err)
        return tokenString, err
      }
    }
  }
  
  return tokenString, nil
}

func (c *JWTItem) JWTCheck(token string) (base.User, int, error) {
  var err error
  user := base.User{}
  
  var claims Claims
  tkn, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(c.ServiceJWTKey), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
      glog.Errorf("ERR: JWT: ParseWithClaims: ErrSignatureInvalid: %v\n", err)
			return user, http.StatusUnauthorized, err
		}
    glog.Errorf("ERR: JWT: ParseWithClaims: %v\n", err)
		return user, http.StatusBadRequest, err
	}
  if !tkn.Valid {
    glog.Errorf("ERR: JWT: !tkn.Valid: %v\n", tkn)
    return user, http.StatusUnauthorized, nil
  }  
  user.ID, err = uuid.Parse(claims.ID)
  if err != nil {
    glog.Errorf("ERR: JWT: User ID<%v> error: %v\n", claims.ID, err)
    return user, http.StatusBadRequest, nil
  } 
  user.Login = claims.Login
  user.Group = claims.Group
  user.Groups = claims.Groups
  user.Avatar = claims.Avatar
  user.EMail = claims.EMail
  user.DisplayName = claims.DisplayName
  return user, http.StatusOK, nil
}
