module Yesod.Auth.Facebook
    ( authFacebook
    , facebookLogin
    , facebookLogout
    , getUserAccessToken
    , setUserAccessToken
    ) where

#include "qq.h"
import Control.Applicative ((<$>))
import Control.Monad (when)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Maybe (MaybeT(..))
import Data.Monoid (mappend)
import Data.Text (Text)
import Network.Wai (queryString)
import Yesod.Auth
import Yesod.Handler
import Yesod.Widget
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Facebook as FB
import qualified Network.HTTP.Conduit as H
import qualified Yesod.Auth.Message as Msg


-- | Route for login using this authentication plugin.
facebookLogin :: AuthRoute
facebookLogin = PluginR "fb" ["login"]


-- | Route for logout using this authentication plugin.  This
-- will log your user out of your site /and/ log him out of
-- Facebook since, at the time of writing, Facebook's policies
-- (<https://developers.facebook.com/policy/>) specified that the
-- user needs to be logged out from Facebook itself as well.  If
-- you want to always logout from just your site (and not from
-- Facebook), use 'LogoutR'.
facebookLogout :: AuthRoute
facebookLogout = PluginR "fb" ["logout"]


-- | Yesod authentication plugin using Facebook.
authFacebook :: YesodAuth master
             => FB.Credentials  -- ^ Your application's credentials.
             -> H.Manager       -- ^ HTTP connection manager.
             -> [FB.Permission] -- ^ Permissions to be requested.
             -> AuthPlugin master
authFacebook creds manager perms = AuthPlugin "fb" dispatch login
  where
    -- Get the URL in facebook.com where users are redirected to.
    getRedirectUrl :: (YesodAuth master, Monad m) =>
                      (Route Auth -> Route master)
                   -> GGHandler sub master m Text
    getRedirectUrl tm = do
        render <- getUrlRender
        let proceedUrl = render (tm proceedR)
        return $ FB.getUserAccessTokenStep1 creds proceedUrl perms
    proceedR = PluginR "fb" ["proceed"]

    -- Redirect the user to Facebook.
    dispatch "GET" ["login"] =
        redirectText RedirectTemporary =<< getRedirectUrl =<< getRouteToMaster
    -- Take Facebook's code and finish authentication.
    dispatch "GET" ["proceed"] = do
        tm     <- getRouteToMaster
        render <- getUrlRender
        query  <- queryString <$> waiRequest
        let proceedUrl = render (tm proceedR)
            query' = [(a,b) | (a, Just b) <- query]
        token <- liftIO $
                 FB.runFacebookT creds manager $
                 FB.getUserAccessTokenStep2 proceedUrl query'
        setUserAccessToken token
        setCreds True (createCreds token)
    -- Logout the user from our site and from Facebook.
    dispatch "GET" ["logout"] = do
        m      <- getYesod
        tm     <- getRouteToMaster
        mtoken <- getUserAccessToken
        when (redirectToReferer m) setUltDestReferer

        -- Facebook doesn't redirect back to our chosen address
        -- when the user access token is invalid, so we need to
        -- check its validity before anything else.
        let isValid = liftIO .
                      FB.runNoAuthFacebookT manager .
                      FB.isValid
        valid <- maybe (return False) isValid mtoken

        case (valid, mtoken) of
          (True, Just token) -> do
            render <- getUrlRender
            redirectText RedirectTemporary $
              FB.getUserLogoutUrl token (render $ tm LogoutR)
          _ -> redirect RedirectTemporary (tm LogoutR)
    -- Anything else gives 404
    dispatch _ _ = notFound

    -- Small widget for multiple login websites.
    login :: YesodAuth master =>
             (Route Auth -> Route master)
          -> GWidget sub master ()
    login tm = do
        redirectUrl <- lift (getRedirectUrl tm)
        [QQ(whamlet)|
<p>
    <a href="#{redirectUrl}">_{Msg.Facebook}
|]


-- | Create an @yesod-auth@'s 'Creds' for a given
-- @'FB.UserAccessToken'@.
createCreds :: FB.UserAccessToken -> Creds m
createCreds (FB.UserAccessToken userId _ _) = Creds "fb" id_ []
    where id_ = "http://graph.facebook.com/" `mappend` TE.decodeUtf8 userId


-- | Set the Facebook's user access token on the user's session.
-- Usually you don't need to call this function, but it may
-- become handy together with 'FB.extendUserAccessToken'.
setUserAccessToken :: MonadIO m =>
                      FB.UserAccessToken
                   -> GGHandler sub master m ()
setUserAccessToken (FB.UserAccessToken userId data_ exptime) = do
  setSession "_FBID" (TE.decodeUtf8 userId)
  setSession "_FBAT" (TE.decodeUtf8 data_)
  setSession "_FBET" (T.pack $ show exptime)


-- | Get the Facebook's user access token from the session.
-- Returns @Nothing@ if it's not found (probably because the user
-- is not logged in via @yesod-auth-fb@).  Note that the returned
-- access token may have expired, we recommend using
-- 'FB.hasExpired' and 'FB.isValid'.
getUserAccessToken :: MonadIO mo =>
                      GGHandler sub master mo (Maybe FB.UserAccessToken)
getUserAccessToken = runMaybeT $ do
  userId  <- MaybeT $ lookupSession "_FBID"
  data_   <- MaybeT $ lookupSession "_FBAT"
  exptime <- MaybeT $ lookupSession "_FBET"
  return $ FB.UserAccessToken (TE.encodeUtf8 userId)
                              (TE.encodeUtf8 data_)
                              (read $ T.unpack exptime)
