package manage_test

import (
	"testing"

	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/store"

	. "github.com/smartystreets/goconvey/convey"
)

func TestManager(t *testing.T) {
	Convey("Manager test", t, func(c C) {
		manager := manage.NewDefaultManager()

		manager.MustTokenStorage(store.NewMemoryTokenStore())

		clientStore := store.NewClientStore()
		_ = clientStore.Set("1", &models.Client{
			ID:     "1",
			Secret: "11",
			Domain: "http://localhost",
		})
		manager.MapClientStorage(clientStore)

		tgr := &oauth2.TokenGenerateRequest{
			ClientID:    "1",
			UserID:      "123456",
			RedirectURI: "http://localhost/oauth2",
			Scope:       "all",
		}

		c.Convey("GetClient test", func(c C) {
			cli, err := manager.GetClient("1")
			c.So(err, ShouldBeNil)
			c.So(cli.GetSecret(), ShouldEqual, "11")
		})

		c.Convey("Token test", func(c C) {
			testManager(tgr, manager, c)
		})
	})
}

func testManager(tgr *oauth2.TokenGenerateRequest, manager oauth2.Manager, c C) {
	cti, err := manager.GenerateAuthToken(oauth2.Code, tgr)
	c.So(err, ShouldBeNil)

	code := cti.GetCode()
	c.So(code, ShouldNotBeEmpty)

	atParams := &oauth2.TokenGenerateRequest{
		ClientID:     tgr.ClientID,
		ClientSecret: "11",
		RedirectURI:  tgr.RedirectURI,
		Code:         code,
	}
	ati, err := manager.GenerateAccessToken(oauth2.AuthorizationCode, atParams)
	c.So(err, ShouldBeNil)

	accessToken, refreshToken := ati.GetAccess(), ati.GetRefresh()
	c.So(accessToken, ShouldNotBeEmpty)
	c.So(refreshToken, ShouldNotBeEmpty)

	ainfo, err := manager.LoadAccessToken(accessToken)
	c.So(err, ShouldBeNil)
	c.So(ainfo.GetClientID(), ShouldEqual, atParams.ClientID)

	arinfo, err := manager.LoadRefreshToken(accessToken)
	c.So(err, ShouldNotBeNil)
	c.So(arinfo, ShouldBeNil)

	rainfo, err := manager.LoadAccessToken(refreshToken)
	c.So(err, ShouldNotBeNil)
	c.So(rainfo, ShouldBeNil)

	rinfo, err := manager.LoadRefreshToken(refreshToken)
	c.So(err, ShouldBeNil)
	c.So(rinfo.GetClientID(), ShouldEqual, atParams.ClientID)

	atParams.Refresh = refreshToken
	atParams.Scope = "owner"
	rti, err := manager.RefreshAccessToken(atParams)
	c.So(err, ShouldBeNil)

	refreshAT := rti.GetAccess()
	c.So(refreshAT, ShouldNotBeEmpty)

	_, err = manager.LoadAccessToken(accessToken)
	c.So(err, ShouldNotBeNil)

	refreshAInfo, err := manager.LoadAccessToken(refreshAT)
	c.So(err, ShouldBeNil)
	c.So(refreshAInfo.GetScope(), ShouldEqual, "owner")

	err = manager.RemoveAccessToken(refreshAT)
	c.So(err, ShouldBeNil)

	_, err = manager.LoadAccessToken(refreshAT)
	c.So(err, ShouldNotBeNil)

	err = manager.RemoveRefreshToken(refreshToken)
	c.So(err, ShouldBeNil)

	_, err = manager.LoadRefreshToken(refreshToken)
	c.So(err, ShouldNotBeNil)
}
