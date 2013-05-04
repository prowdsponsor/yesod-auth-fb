-- | @yesod-auth@ authentication plugin using Facebook's
-- client-side authentication flow.  You may see a demo at
-- <https://github.com/meteficha/yesod-auth-fb/blob/master/demo/clientside.hs>.
--
-- /WARNING:/ Currently this authentication plugin /does not/
-- work with other authentication plugins.  If you need many
-- different authentication plugins, please try the server-side
-- authentication flow (module "Yesod.Auth.Facebook.ServerSide").
--
-- TODO: Explain how the whole thing fits together.
module Yesod.Auth.Facebook.ClientSide
    ( -- * Authentication plugin
      authFacebookClientSide
    , YesodAuthFbClientSide(..)

      -- * Widgets
    , facebookJSSDK
    , facebookLogin
    , facebookForceLoginR
    , facebookLogout
    , JavaScriptCall

      -- * Useful functions
    , serveChannelFile
    , defaultFbInitOpts

      -- * Access tokens
    , extractCredsAccessToken
    , getUserAccessTokenFromFbCookie

      -- * Advanced
    , signedRequestCookieName
    ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (when)
import Control.Monad.Trans.Error (ErrorT(..), throwError)
import Data.ByteString (ByteString)
import Data.Monoid (mappend, mempty)
import Data.String (fromString)
import Data.Text (Text)
import Network.Wai (queryString)
import Text.Julius (JavascriptUrl, julius, rawJS)
import Yesod.Auth
import Yesod.Core
import qualified Control.Exception.Lifted as E
import qualified Data.Aeson as A
import qualified Data.Aeson.Types as A
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Time as TI
import qualified Data.Time.Clock.POSIX as TI
import qualified Facebook as FB
import qualified Yesod.Facebook as YF
import qualified Yesod.Auth.Message as Msg


-- | Internal function.  Construct a route to our plugin.
fbcsR :: [Text] -> Route Auth
fbcsR = PluginR "fbcs"


-- | Hamlet that should be spliced /right after/ the @<body>@ tag
-- in order for Facebook's JS SDK to work.  For example:
--
-- @
--   $doctype 5
--   \<html\>
--     \<head\>
--       ...
--     \<body\>
--       ^{facebookJSSDK AuthR}
--       ...
-- @
--
-- Facebook's JS SDK may not work correctly if you place it
-- anywhere else on the body.  If you absolutely need to do so,
-- avoid any elements placed with @position: relative@ or
-- @position: absolute@.
facebookJSSDK :: YesodAuthFbClientSide site =>
                 (Route Auth -> Route site)
              -> WidgetT site IO ()
facebookJSSDK toSite = do
  (lang, fbInitOptsList, muid, ur) <-
    handlerToWidget $
      (,,,) <$> getFbLanguage
            <*> getFbInitOpts
            <*> maybeAuthId
            <*> getUrlRender
  let loggedIn = maybe False (const True) muid
      loginRoute  = toSite $ fbcsR ["login"]
      logoutRoute = toSite $ LogoutR
      fbInitOpts  = A.object $ map (uncurry (A..=)) fbInitOptsList
  [whamlet|$newline never
    <div #fb-root>
   |]
  toWidgetBody [julius|
    // Load the SDK Asynchronously
    (function(d){
       var js, id = 'facebook-jssdk', ref = d.getElementsByTagName('script')[0];
       if (d.getElementById(id)) {return;}
       js = d.createElement('script'); js.id = id; js.async = true;
       js.src = "//connect.facebook.net/#{rawJS lang}/all.js";
       ref.parentNode.insertBefore(js, ref);
     }(document));

    // Init the SDK upon load
    window.fbAsyncInit = function() {
      FB.init(#{A.toJSON fbInitOpts});
      ^{fbAsyncInitJs}

      // Subscribe to statusChange event.
      FB.Event.subscribe("auth.statusChange", function (response) {
        if (response) {
          // If the user is logged in on our site or not.
          var loggedIn = #{A.toJSON loggedIn};

          if (response.status === 'connected') {
            // Facebook says the user is logged in.
            if (!loggedIn) {
              // But he is not logged in on our site.
              window.location.href = '@{loginRoute}';
            }
          } else {
            // User is not logged in.
            if (loggedIn) {
              // But he is logged in on our site, log him out.
              // An undesirable side-effect of this change is
              // that we're always going to log the user out of
              // the site if he has logged in via another
              // Yesod authentication plugin.
              window.location.href = '@{logoutRoute}';
            }
          }
        }
      });
    }

    // Logout function
    window.$$yfblogout = function () {
      FB.getLoginStatus(function(response) {
        if (response.status !== 'connected' ||
            FB.logout(function () {}) === undefined) {
          window.location.href = #{A.toJSON (ur (toSite LogoutR))}
        }
      });
      return (function () {});
    };
   |]


-- | JavaScript function that should be called in order to login
-- the user.  You could splice this into a @onclick@ event, for
-- example:
--
-- @
--   \<a href=\"\#\" onclick=\"\#{facebookLogin perms}\"\>
--     Login via Facebook
-- @
--
-- You should not call this function if the user is already
-- logged in.
--
--
-- This is only a helper around Facebook JS SDK's @FB.login()@,
-- you may call that function directly if you prefer.
facebookLogin :: [FB.Permission] -> JavaScriptCall
facebookLogin [] = "FB.login(function () {})"
facebookLogin perms =
  T.concat [ "FB.login(function () {}, {scope: '"
           , joinPermissions perms
           , "'})"
           ]


-- | Route that forces the user to log in.  You should avoid
-- using this route whenever possible, using 'facebookLogin' is
-- much better (after all, this module is for client-side
-- authentication).  However, you may want to use it at least for
-- 'authRoute', e.g.:
--
-- @
-- instance 'Yesod' MyFoundation where
--   ...
--   'authRoute' _ = Just $ AuthR (facebookForceLoginR [])
-- @
facebookForceLoginR :: [FB.Permission] -> Route Auth
facebookForceLoginR perms = fbcsR ["login", "go", joinPermissions perms]


-- | Internal function.  Joins a list of 'FB.Permission'@s@ into
-- a format that Facebook recognizes.
joinPermissions :: [FB.Permission] -> Text
joinPermissions = T.intercalate "," . map FB.unPermission


-- | JavaScript function that should be called in order to logout
-- the user.  You could splice the result of this widget into a
-- @onclick@ event, for example:
--
-- @
--   \<a href=\"\#\" onclick=\"\#{facebookLogout}\"\>
--     Logout
-- @
--
-- This function used to be just a helper around Facebook JS
-- SDK's @FB.logout()@.  However, now it performs a check to see
-- if the user is logged via FB and redirects to @yesod-auth@'s
-- normal 'LogoutR' route if not.
facebookLogout :: JavaScriptCall
facebookLogout = "window.$$yfblogout()"


-- | A JavaScript function call.
type JavaScriptCall = Text


----------------------------------------------------------------------


-- | Type class that needs to be implemented in order to use
-- 'authFacebookClientSide'.
--
-- Minimal complete definition: 'getFbChannelFile'.  (We
-- recommend implementing 'getFbLanguage' as well.)
class (YesodAuth site, YF.YesodFacebook site) => YesodAuthFbClientSide site where
  -- | A route that serves Facebook's channel file in the /same/
  -- /subdomain/ as the current request's subdomain.
  --
  -- First of all, we recomment using 'serveChannelFile' to
  -- implement the route's handler.  For example, if your route
  -- is 'ChannelFileR', then you just need:
  --
  -- @
  --   getChannelFileR :: HandlerT site IO ChooseRep
  --   getChannelFileR = serveChannelFile
  -- @
  --
  -- On most simple cases you may just implement 'fbChannelFile'
  -- as
  --
  -- @
  --   getFbChannelFile = return ChannelFileR
  -- @
  --
  -- However, if your routes span many subdomains, then you must
  -- have a channel file for each subdomain, otherwise your site
  -- won't work on old Internet Explorer versions (and maybe even
  -- on other browsers as well).  That's why 'getFbChannelFile'
  -- lives inside 'HandlerT'.
  getFbChannelFile :: HandlerT site IO (Route site)
                      -- ^ Return channel file in the /same/
                      -- /subdomain/ as the current route.

  -- | /(Optional)/ Returns which language we should ask for
  -- Facebook's JS SDK.  You may use information about the
  -- current request to decide upon a language.  Defaults to
  -- @"en_US"@.
  --
  -- If you already use Yesod's I18n capabilities, then there's
  -- an easy way of implementing this function.  Just create a
  -- @FbLanguage@ message, for example on your @en.msg@ file:
  --
  -- @
  --   FbLanguage: en_US
  -- @
  --
  -- and on your @pt.msg@ file:
  --
  -- @
  --   FbLanguage: pt_BR
  -- @
  --
  -- Then implement 'getFbLanguage' as:
  --
  -- @
  --   getFbLanguage = ($ MsgFbLanguage) \<$\> getMessageRender
  -- @
  --
  -- Although somewhat hacky, this trick works perfectly fine and
  -- /guarantees/ that all Facebook messages will be in the same
  -- language as the rest of your site (even if Facebook support
  -- a language that you don't).
  getFbLanguage :: HandlerT site IO Text
  getFbLanguage = return "en_US"

  -- | /(Optional)/ Options that should be given to @FB.init()@.
  -- The default implementation is 'defaultFbInitOpts'.  If you
  -- intend to override this function, we advise you to also call
  -- 'defaultFbInitOpts', e.g.:
  --
  -- @
  --     getFbInitOpts = do
  --       defOpts <- defaultFbInitOpts
  --       ...
  --       return (defOpts ++ myOpts)
  -- @
  --
  -- However, if you know what you're doing you're free to
  -- override any or all values returned by 'defaultFbInitOpts'.
  getFbInitOpts :: HandlerT site IO [(Text, A.Value)]
  getFbInitOpts = defaultFbInitOpts

  -- | /(Optional)/ Arbitrary JavaScript that will be called on
  -- Facebook's JS SDK's @fbAsyncInit@ (i.e. as soon as their SDK
  -- is loaded).
  fbAsyncInitJs :: JavascriptUrl (Route site)
  fbAsyncInitJs = const mempty


-- | Default implementation for 'getFbInitOpts'.  Defines:
--
--  [@appId@] Using 'YF.getFbCredentials'.
--
--  [@channelUrl@] Using 'getFbChannelFile'.
--
--  [@cookie@] To @True@.  This one is extremely important and
--  this module won't work /at all/ without it.
--
--  [@status@] To @True@, since this usually is what you want.
defaultFbInitOpts :: YesodAuthFbClientSide site =>
                     HandlerT site IO [(Text, A.Value)]
defaultFbInitOpts = do
  ur <- getUrlRender
  creds <- YF.getFbCredentials
  channelFile <- getFbChannelFile
  return [ ("appId",      A.toJSON $ FB.appId creds)
         , ("channelUrl", A.toJSON $ ur channelFile)
         , ("status",     A.toJSON True) -- Check login status.
         , ("cookie",     A.toJSON True) -- Enable cookie, extremely important.
         ]


-- | Facebook's channel file implementation (see
-- <https://developers.facebook.com/docs/reference/javascript/>).
--
-- Note that we set an expire time in the far future, so you
-- won't be able to re-use this route again.  No common users
-- will see this route, so you may use anything.
serveChannelFile :: HandlerT site IO TypedContent
serveChannelFile = do
  addHeader "Pragma" "public"
  cacheSeconds oneYearSecs
  neverExpires
  selectRep $ provideRepType "text/html" (return channelFileContent)
 where oneYearSecs = 60*60*24*365 :: Int


-- | Channel file's content.  On the toplevel in order to have
-- its length and memory representation cached.
channelFileContent :: Content
channelFileContent = toContent val
  where val :: ByteString
        val = "<script src=\"//connect.facebook.net/en_US/all.js\"></script>"


-- | Yesod authentication plugin using Facebook's client-side
-- authentication flow.
--
-- You /MUST/ use 'facebookJSSDK' as its documentation states.
authFacebookClientSide :: YesodAuthFbClientSide site
                       => AuthPlugin site
authFacebookClientSide =
    AuthPlugin "fbcs" dispatch login
  where
    dispatch :: YesodAuthFbClientSide site =>
                Text -> [Text] -> HandlerT Auth (HandlerT site IO) ()
    -- Login route used when successfully logging in.  Called via
    -- AJAX by JavaScript code on 'facebookJSSDK'.
    dispatch "GET" ["login"] = do
      y <- lift getYesod
      when (redirectToReferer y) (lift setUltDestReferer)
      etoken <- lift getUserAccessTokenFromFbCookie
      case etoken of
        Right token -> lift $ setCreds True (createCreds token)
        Left msg -> fail msg

    -- Login routes used to forcefully require the user to login.
    dispatch "GET" ["login", "go"] = dispatch "GET" ["login", "go", ""]
    dispatch "GET" ["login", "go", perms] = do
      -- Redirect the user to the server-side flow login url.
      y  <- lift getYesod
      ur <- getUrlRender
      when (redirectToReferer y) (lift setUltDestReferer)
      let redirectTo = ur $ fbcsR ["login", "back"]
          uncommas "" = []
          uncommas xs = case break (== ',') xs of
                          (x', ',':xs') -> x' : uncommas xs'
                          (x', _)       -> [x']
      url <- lift $
             YF.runYesodFbT $
             FB.getUserAccessTokenStep1 redirectTo $
               map fromString $ uncommas $ T.unpack perms
      redirect url
    dispatch "GET" ["login", "back"] = do
      -- We used to use the client-side flow to finish the
      -- authentication.  The advantage was simplifying the rest
      -- of the code which didn't need to know about the use of
      -- the server-side flow above.  However, this was very
      -- flimsy and sometimes the user landed on a blank page due
      -- to race conditions.
      ur <- getUrlRender
      query <- queryString <$> waiRequest
      let proceedUrl = ur $ fbcsR ["login", "back"]
          query' = [(a,b) | (a, Just b) <- query]
      token <- lift $
               YF.runYesodFbT $
               FB.getUserAccessTokenStep2 proceedUrl query'
      lift $ setCreds True (createCreds token)

    -- Everything else gives 404
    dispatch _ _ = notFound

    -- Small widget for multiple login websites.
    login :: YesodAuth site =>
             (Route Auth -> Route site)
          -> WidgetT site IO ()
    login _ = [whamlet|$newline never
                 <p>
                   <a href="#" onclick="#{facebookLogin perms}">
                     _{Msg.Facebook}
              |]
      where perms = []


-- | Create an @yesod-auth@'s 'Creds' for a given
-- @'FB.UserAccessToken'@.
createCreds :: FB.UserAccessToken -> Creds m
createCreds at@(FB.UserAccessToken (FB.Id userId) _ _) =
  let id_ = "http://graph.facebook.com/" `mappend` userId
  in Creds "fbcs" id_ (atToText at)


-- | Get the user access token from a 'Creds' created by this
-- backend.  This function should be used on 'getAuthId'.
extractCredsAccessToken :: Creds m -> Maybe FB.UserAccessToken
extractCredsAccessToken (Creds "fbcs" _ extra) = textToAt extra
extractCredsAccessToken _                      = Nothing


-- | Convert user access token to @[(Text, Text)]@.
--
-- @
-- textToAt . atToText === Just
-- @
atToText :: FB.UserAccessToken -> [(Text, Text)]
atToText (FB.UserAccessToken userId data_ expires) =
  [ ("at_id",      FB.idCode userId)
  , ("at_data",    data_)
  , ("at_expires", T.pack (show expires)) ]


-- | See 'atToText'.
textToAt :: [(Text, Text)] -> Maybe FB.UserAccessToken
textToAt texts = do
  at_id      <- lookup "at_id"      texts
  at_data    <- lookup "at_data"    texts
  at_expires <- lookup "at_expires" texts
  [(expires, "")] <- return $ readsPrec 0 (T.unpack at_expires)
  return $ FB.UserAccessToken (FB.Id at_id) at_data expires


-- | Cookie name with the signed request for the given credentials.
signedRequestCookieName :: FB.Credentials -> Text
signedRequestCookieName = T.append "fbsr_" . FB.appId


-- | Get the Facebook's user access token from Facebook's cookie.
-- Returns 'Left' if the cookie is not found, is not
-- authentic, is for another app, is corrupted /or/ does not
-- contains the information needed (maybe the user is not logged
-- in).  Note that the returned access token may have expired, we
-- recommend using 'FB.hasExpired' and 'FB.isValid'.
--
-- This 'getUserAccessTokenFromFbCookie' is completely different
-- from the one from the "Yesod.Auth.Facebook.ServerSide" module.
-- This one does not use only the session, which means that (a)
-- it's somewhat slower because everytime you call this
-- 'getUserAccessTokenFromFbCookie' it needs to reverify the
-- cookie, but (b) it is always up-to-date with the latest cookie
-- that the Facebook JS SDK has given us and (c) avoids
-- duplicating the information from the cookie into the session.
--
-- Note also that 'getUserAccessTokenFromFbCookie' may return
-- 'Left' even tough the user is properly logged in.  When you
-- force authentication via 'facebookForceLoginR' (e.g., via
-- 'requireAuth'/'requireAuthId') we use the server-side flow
-- which will not set the cookie until at least the FB JS SDK
-- runs on the user-agent, sets the cookie and another request is
-- sent to our servers.
--
-- For the reason stated on the previous paragraph, you should
-- not use this function on 'getAuthId'.  Instead, you should use
-- 'extractCredsAccessToken'.
getUserAccessTokenFromFbCookie ::
  YesodAuthFbClientSide site =>
  HandlerT site IO (Either String FB.UserAccessToken)
getUserAccessTokenFromFbCookie =
  runErrorT $ do
    creds <- lift YF.getFbCredentials
    unparsed <- toErrorT "cookie not found" $ lookupCookie (signedRequestCookieName creds)
    A.Object parsed <- toErrorT "cannot parse signed request" $
                       YF.runYesodFbT $
                       FB.parseSignedRequest (TE.encodeUtf8 unparsed)
    case (flip A.parseEither () $ const $
          (,,,) <$> parsed A..:? "code"
                <*> parsed A..:? "user_id"
                <*> parsed A..:? "oauth_token"
                <*> parsed A..:? "expires") of
      Right (Just code, _, _, _) -> do
        -- We have to exchange the code for the access token.
        moldCode <- lift $ lookupSessionBS sessionCode
        case moldCode of
          Just code' | code == code' -> lift $ do
            -- We have a cached token for this code.
            Just userId  <- lookupSession sessionUserId
            Just data_   <- lookupSession sessionToken
            Just exptime <- lookupSession sessionExpires
            return $ FB.UserAccessToken (FB.Id userId) data_ (read $ T.unpack exptime)
          _ -> do
            -- Get access token from Facebook.
            let fbErrorMsg :: FB.FacebookException -> String
                fbErrorMsg exc = "getUserAccessTokenFromFbCookie: getUserAccessTokenStep2 " ++
                                 "failed with " ++ show exc
            token <- ErrorT $
                     fmap (either (Left . fbErrorMsg) Right) $
                     E.try $
                     YF.runYesodFbT $
                     FB.getUserAccessTokenStep2 "" [("code", code)]
            case token of
              FB.UserAccessToken userId data_ exptime -> lift $ do
                -- Save it for later.
                setSessionBS sessionCode    code
                setSession   sessionUserId  (FB.idCode userId)
                setSession   sessionToken   data_
                setSession   sessionExpires (T.pack $ show exptime)
                return token
      Right (_, Just uid, Just oauth_token, Just expires) ->
        return $ FB.UserAccessToken uid oauth_token (toUTCTime expires)
      Right (Nothing, _, _, _) ->
        throwError "getUserAccessTokenFromFbCookie: no user_id nor code on signed request"
      Left msg ->
        throwError ("getUserAccessTokenFromFbCookie: never here (" ++ show msg ++ ")")
  where
    toErrorT :: Functor m => String -> m (Maybe a) -> ErrorT String m a
    toErrorT msg = ErrorT . fmap (maybe (Left ("getUserAccessTokenFromFbCookie: " ++ msg)) Right)

    toUTCTime :: Integer -> TI.UTCTime
    toUTCTime = TI.posixSecondsToUTCTime . fromIntegral

    sessionCode    = "_FBCSD"
    sessionUserId  = "_FBCSU"
    sessionToken   = "_FBCST"
    sessionExpires = "_FBCSE"
