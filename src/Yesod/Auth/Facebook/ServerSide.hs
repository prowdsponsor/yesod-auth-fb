-- | @yesod-auth@ authentication plugin using Facebook's
-- server-side authentication flow.
module Yesod.Auth.Facebook.ServerSide
    ( -- * Authentication plugin
      authFacebook
    , facebookLogin
    , facebookLogout

      -- * Useful functions
    , getUserAccessToken
    , setUserAccessToken

      -- * Advanced
    , deleteUserAccessToken
    ) where

import Control.Applicative ((<$>))
import Control.Monad (when)
import Control.Monad.Trans.Maybe (MaybeT(..))
import Data.Monoid (mappend)
import Data.Text (Text)
import Network.Wai (queryString)
import Yesod.Auth
import Yesod.Core
import qualified Data.Text as T
import qualified Facebook as FB
import qualified Yesod.Auth.Message as Msg
import qualified Yesod.Facebook as YF

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
authFacebook :: (YesodAuth site, YF.YesodFacebook site)
             => [FB.Permission] -- ^ Permissions to be requested.
             -> AuthPlugin site
authFacebook perms = AuthPlugin "fb" dispatch login
  where
    -- Get the URL in facebook.com where users are redirected to.
    getRedirectUrl :: YF.YesodFacebook site => (Route Auth -> Text) -> HandlerT site IO Text
    getRedirectUrl render =
        YF.runYesodFbT $ FB.getUserAccessTokenStep1 (render proceedR) perms
    proceedR = PluginR "fb" ["proceed"]

    dispatch :: (YesodAuth site, YF.YesodFacebook site) =>
                Text -> [Text] -> HandlerT Auth (HandlerT site IO) ()
    -- Redirect the user to Facebook.
    dispatch "GET" ["login"] = do
        ur <- getUrlRender
        lift $ do
          y <- getYesod
          when (redirectToReferer y) setUltDestReferer
          redirect =<< getRedirectUrl ur
    -- Take Facebook's code and finish authentication.
    dispatch "GET" ["proceed"] = do
        render <- getUrlRender
        query  <- queryString <$> waiRequest
        let proceedUrl = render proceedR
            query' = [(a,b) | (a, Just b) <- query]
        lift $ do
          token <- YF.runYesodFbT $ FB.getUserAccessTokenStep2 proceedUrl query'
          setUserAccessToken token
          setCreds True (createCreds token)
    -- Logout the user from our site and from Facebook.
    dispatch "GET" ["logout"] = do
        y      <- lift getYesod
        mtoken <- lift getUserAccessToken
        when (redirectToReferer y) (lift setUltDestReferer)

        -- Facebook doesn't redirect back to our chosen address
        -- when the user access token is invalid, so we need to
        -- check its validity before anything else.
        valid <- maybe (return False) (lift . YF.runYesodFbT . FB.isValid) mtoken

        case (valid, mtoken) of
          (True, Just token) -> do
            render <- getUrlRender
            dest <- lift $ YF.runYesodFbT $ FB.getUserLogoutUrl token (render $ PluginR "fb" ["kthxbye"])
            redirect dest
          _ -> dispatch "GET" ["kthxbye"]
    -- Finish the logout procedure.  Unfortunately we have to
    -- replicate yesod-auth's postLogoutR code here since it's
    -- not accessible for us.  We also can't just redirect to
    -- LogoutR since it would otherwise call setUltDestReferrer
    -- again.
    dispatch "GET" ["kthxbye"] =
        lift $ do
          m <- getYesod
          deleteSession "_ID"
          deleteUserAccessToken
          onLogout
          redirectUltDest $ logoutDest m
    -- Anything else gives 404
    dispatch _ _ = notFound

    -- Small widget for multiple login websites.
    login :: (YesodAuth site, YF.YesodFacebook site) =>
             (Route Auth -> Route site)
          -> WidgetT site IO ()
    login tm = do
        ur <- getUrlRender
        redirectUrl <- handlerToWidget $ getRedirectUrl (ur . tm)
        [whamlet|$newline never
<p>
    <a href="#{redirectUrl}">_{Msg.Facebook}
|]


-- | Create an @yesod-auth@'s 'Creds' for a given
-- @'FB.UserAccessToken'@.
createCreds :: FB.UserAccessToken -> Creds m
createCreds (FB.UserAccessToken (FB.Id userId) _ _) = Creds "fb" id_ []
    where id_ = "http://graph.facebook.com/" `mappend` userId


-- | Set the Facebook's user access token on the user's session.
-- Usually you don't need to call this function, but it may
-- become handy together with 'FB.extendUserAccessToken'.
setUserAccessToken :: FB.UserAccessToken
                   -> HandlerT site IO ()
setUserAccessToken (FB.UserAccessToken (FB.Id userId) data_ exptime) = do
  setSession "_FBID" userId
  setSession "_FBAT" data_
  setSession "_FBET" (T.pack $ show exptime)


-- | Get the Facebook's user access token from the session.
-- Returns @Nothing@ if it's not found (probably because the user
-- is not logged in via @yesod-auth-fb@).  Note that the returned
-- access token may have expired, we recommend using
-- 'FB.hasExpired' and 'FB.isValid'.
getUserAccessToken :: HandlerT site IO (Maybe FB.UserAccessToken)
getUserAccessToken = runMaybeT $ do
  userId  <- MaybeT $ lookupSession "_FBID"
  data_   <- MaybeT $ lookupSession "_FBAT"
  exptime <- MaybeT $ lookupSession "_FBET"
  return $ FB.UserAccessToken (FB.Id userId) data_ (read $ T.unpack exptime)


-- | Delete Facebook's user access token from the session.  /Do/
-- /not use/ this function unless you know what you're doing.
deleteUserAccessToken :: HandlerT site IO ()
deleteUserAccessToken = do
  deleteSession "_FBID"
  deleteSession "_FBAT"
  deleteSession "_FBET"
