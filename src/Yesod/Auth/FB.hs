module Yesod.Auth.FB
    ( authFacebook
    , facebookLogin
    , facebookLogout
    , getFacebookAccessToken
    ) where

#include "qq.h"

import Yesod.Auth
import Data.Maybe (fromMaybe)

import Yesod.Form
import Yesod.Handler
import Yesod.Widget
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Class (lift)
import Data.Text (Text)
import Control.Monad (liftM, mzero, when)
import Data.Monoid (mappend)

import Control.Applicative ((<$>))
import qualified Facebook as FB
import qualified Network.HTTP.Conduit as H
import qualified Network.Wai (queryString)
import qualified Yesod.Auth.Message as Msg


-- | Route for login using this authentication plugin.
facebookLogin :: AuthRoute
facebookLogin = PluginR "fb" ["login"]


-- | Route for logout using this authentication plugin.  At the
-- time of writing, Facebook's policies
-- (<https://developers.facebook.com/policy/>) specified that the
-- user needs to be logged out from Facebook itself as well.
facebookLogout :: AuthRoute
facebookLogout = PluginR "fb" ["logout"]


-- | Get Facebook's access token from the session.  Returns
-- @Nothing@ if it's not found (probably because the user is not
-- logged in via Facebook).  Note that the returned access token
-- may have expired, we recommend using 'FB.hasExpired' and
-- 'FB.isValid'.
getUserAccessToken :: MonadIO mo => GGHandler sub master mo (Maybe (FB.AccessToken FB.User))
getUserAccessToken =
    liftM (fmap Facebook.AccessToken) (lookupSession facebookAccessTokenKey)


-- | Key used to store Facebook's access token in the client
-- session.
facebookAccessTokenKey :: Text
facebookAccessTokenKey = "_FB"


-- | Yesod authentication plugin using Facebook.
authFacebook :: YesodAuth m
             => FB.Credentials  -- ^ Your application's credentials.
             -> H.Manager       -- ^ HTTP connection manager.
             -> [FB.Permission] -- ^ Permissions to be requested.
             -> AuthPlugin m
authFacebook creds manager perms =
    AuthPlugin "fb" dispatch login
  where
    -- Get the URL in facebook.com where users are redirected to.
    getRedirectUrl = do
        tm     <- getRouteToMaster
        render <- getUrlRender
        let proceedUrl  = render $ tm (PluginR "fb" ["proceed"])
        return $ getUserAccessTokenStep1 creds proceedUrl perms

    -- Redirect the user to Facebook.
    dispatch "GET" ["login"] =
        redirectText RedirectTemporary =<< getRedirectUrl
    -- Take Facebook's code and finish authentication.
    dispatch "GET" ["proceed"] = do
        tm     <- getRouteToMaster
        render <- getUrlRender
        query  <- queryString <$> waiRequest
        let proceedUrl = render (tm proceedUrl)
            query' = [(a,b) | (a, Just b) <- query]
        token <- FB.runFacebookT creds manager $
                 FB.getUserAccessTokenStep2 proceedUrl query'

        ------------------------------------------------------------------------------------------
        setSession facebookAccessTokenKey at'
        let c = fromMaybe (error "Invalid response from Facebook")
                $ parseMaybe (parseCreds at') $ either error id so
        setCreds True c
        ------------------------------------------------------------------------------------------
    -- Logout the user from our site and from Facebook.
    dispatch "GET" ["logout"] = do
        m      <- getYesod
        tm     <- getRouteToMaster
        mtoken <- getUserAccessToken
        when (redirectToReferer m) setUltDestReferer

        -- Facebook doesn't redirect back to our chosen address
        -- when the user access token is invalid, so we need to
        -- check its validity before anything else.
        let isValid = FB.runNoAuthFacebookT manager . FB.isValid
        valid <- maybe (return False) isValid mtoken

        case (valid, mtoken) of
          (True, Just token) ->
              redirectText RedirectTemporary $
              FB.getUserLogoutUrl token (render $ tm LogoutR)
          _ -> redirect RedirectTemporary (tm LogoutR)
    -- Anything else gives 404
    dispatch _ _ = notFound

    -- Small widget for multiple login websites.
    login tm = do
        redirectUrl <- lift getRedirectUrl
        [QQ(whamlet)|
<p>
    <a href="#{redirectUrl}">_{Msg.Facebook}
|]


parseCreds :: Text -> Value -> Data.Aeson.Types.Parser (Creds m)
parseCreds at' (Object m) = do
    id' <- m .: "id"
    let id'' = "http://graph.facebook.com/" `mappend` id'
    name <- m .:? "name"
    email <- m .:? "email"
    return
        $ Creds "facebook" id''
        $ maybe id (\x -> (:) ("verifiedEmail", x)) email
        $ maybe id (\x -> (:) ("displayName ", x)) name
        [ ("accessToken", at')
        ]
parseCreds _ _ = mzero
