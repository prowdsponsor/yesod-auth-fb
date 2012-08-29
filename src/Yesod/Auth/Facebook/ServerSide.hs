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
    , beta_authFacebook
    , deleteUserAccessToken
    ) where

import Control.Applicative ((<$>))
import Control.Monad (when)
import Control.Monad.IO.Class (MonadIO, liftIO)
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
import qualified Yesod.Auth.Message as Msg
import qualified Data.Conduit as C

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
             -> [FB.Permission] -- ^ Permissions to be requested.
             -> AuthPlugin master
authFacebook = authFacebookHelper False


-- | Same as 'authFacebook', but uses Facebook's beta tier.
-- Usually this is /not/ what you want, so use 'authFacebook'
-- unless you know what you're doing.
--
-- /Since: 0.10.1/
beta_authFacebook :: YesodAuth master
                  => FB.Credentials
                  -> [FB.Permission]
                  -> AuthPlugin master
beta_authFacebook = authFacebookHelper True


-- | Helper function for 'authFacebook' and 'beta_authFacebook'.
authFacebookHelper :: YesodAuth master
                   => Bool -- ^ @useBeta@
                   -> FB.Credentials
                   -> [FB.Permission]
                   -> AuthPlugin master
authFacebookHelper useBeta creds perms = AuthPlugin "fb" dispatch login
  where
    -- Run a Facebook action.
    runFB :: YesodAuth master =>
             FB.FacebookT FB.Auth (C.ResourceT IO) a
          -> GHandler sub master a
    runFB act = do
      manager <- authHttpManager <$> getYesod
      liftIO $ C.runResourceT $
        (if useBeta then FB.beta_runFacebookT else FB.runFacebookT)
        creds manager act

    -- Get the URL in facebook.com where users are redirected to.
    getRedirectUrl :: YesodAuth master =>
                      (Route Auth -> Route master)
                   -> GHandler sub master Text
    getRedirectUrl tm = do
        render  <- getUrlRender
        let proceedUrl = render (tm proceedR)
        runFB $ FB.getUserAccessTokenStep1 proceedUrl perms
    proceedR = PluginR "fb" ["proceed"]

    -- Redirect the user to Facebook.
    dispatch "GET" ["login"] = do
        m <- getYesod
        when (redirectToReferer m) setUltDestReferer
        redirect =<< getRedirectUrl =<< getRouteToMaster
    -- Take Facebook's code and finish authentication.
    dispatch "GET" ["proceed"] = do
        tm     <- getRouteToMaster
        render <- getUrlRender
        query  <- queryString <$> waiRequest
        let proceedUrl = render (tm proceedR)
            query' = [(a,b) | (a, Just b) <- query]
        token <- runFB $ FB.getUserAccessTokenStep2 proceedUrl query'
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
        valid <- maybe (return False) (runFB . FB.isValid) mtoken

        case (valid, mtoken) of
          (True, Just token) -> do
            render <- getUrlRender
            dest <- runFB $ FB.getUserLogoutUrl token (render $ tm $ PluginR "fb" ["kthxbye"])
            redirect dest
          _ -> dispatch "GET" ["kthxbye"]
    -- Finish the logout procedure.  Unfortunately we have to
    -- replicate yesod-auth's postLogoutR code here since it's
    -- not accessible for us.  We also can't just redirect to
    -- LogoutR since it would otherwise call setUltDestReferrer
    -- again.
    dispatch "GET" ["kthxbye"] = do
        m <- getYesod
        deleteSession "_ID"
        deleteUserAccessToken
        onLogout
        redirectUltDest $ logoutDest m
    -- Anything else gives 404
    dispatch _ _ = notFound

    -- Small widget for multiple login websites.
    login :: YesodAuth master =>
             (Route Auth -> Route master)
          -> GWidget sub master ()
    login tm = do
        redirectUrl <- lift (getRedirectUrl tm)
        [whamlet|$newline never
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
setUserAccessToken :: FB.UserAccessToken
                   -> GHandler sub master ()
setUserAccessToken (FB.UserAccessToken userId data_ exptime) = do
  setSession "_FBID" (TE.decodeUtf8 userId)
  setSession "_FBAT" (TE.decodeUtf8 data_)
  setSession "_FBET" (T.pack $ show exptime)


-- | Get the Facebook's user access token from the session.
-- Returns @Nothing@ if it's not found (probably because the user
-- is not logged in via @yesod-auth-fb@).  Note that the returned
-- access token may have expired, we recommend using
-- 'FB.hasExpired' and 'FB.isValid'.
getUserAccessToken :: GHandler sub master (Maybe FB.UserAccessToken)
getUserAccessToken = runMaybeT $ do
  userId  <- MaybeT $ lookupSession "_FBID"
  data_   <- MaybeT $ lookupSession "_FBAT"
  exptime <- MaybeT $ lookupSession "_FBET"
  return $ FB.UserAccessToken (TE.encodeUtf8 userId)
                              (TE.encodeUtf8 data_)
                              (read $ T.unpack exptime)


-- | Delete Facebook's user access token from the session.  /Do/
-- /not use/ this function unless you know what you're doing.
deleteUserAccessToken :: GHandler sub master ()
deleteUserAccessToken = do
  deleteSession "_FBID"
  deleteSession "_FBAT"
  deleteSession "_FBET"
