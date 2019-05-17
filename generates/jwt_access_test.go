package generates_test

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"

	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/generates"
	"gopkg.in/oauth2.v3/models"

	. "github.com/smartystreets/goconvey/convey"
)

func TestJWTAccess(t *testing.T) {
	Convey("Test JWT Access Generate", t, func(c C) {
		data := &oauth2.GenerateBasic{
			Client: &models.Client{
				ID:     "123456",
				Secret: "123456",
			},
			UserID: "000000",
			TokenInfo: &models.Token{
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 120,
			},
		}

		gen := generates.NewJWTAccessGenerate([]byte("00000000"), jwt.SigningMethodHS512)
		access, refresh, err := gen.Token(data, true)
		c.So(err, ShouldBeNil)
		c.So(access, ShouldNotBeEmpty)
		c.So(refresh, ShouldNotBeEmpty)

		// token, err := jwt.ParseWithClaims(access, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		// 	if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
		// 		return nil, fmt.Errorf("parse error")
		// 	}
		// 	return []byte("00000000"), nil
		// })
		// c.So(err, ShouldBeNil)

		// claims, ok := token.Claims.(*generates.JWTAccessClaims)
		// c.So(ok, ShouldBeTrue)
		// c.So(token.Valid, ShouldBeTrue)
		// c.So(claims.ClientID, ShouldEqual, "123456")
		// c.So(claims.UserID, ShouldEqual, "000000")
	})
}
