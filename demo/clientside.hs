{-# LANGUAGE TypeFamilies, QuasiQuotes, MultiParamTypeClasses,
             TemplateHaskell, OverloadedStrings, StandaloneDeriving #-}

import System.Environment (getEnv)
import System.Exit (exitFailure)
import System.IO.Error (isDoesNotExistError)
import Yesod
import Yesod.Auth
import Yesod.Auth.Facebook.ClientSide
import Yesod.Form.I18n.English
import qualified Control.Exception.Lifted as E
import qualified Data.ByteString.Char8 as B
import qualified Data.Text as T
import qualified Facebook as FB
import qualified Network.HTTP.Conduit as H


data Test = Test { httpManager :: H.Manager
                 , fbCreds     :: FB.Credentials }


mkYesod "Test" [parseRoutes|
  / HomeR GET
  /auth AuthR Auth getAuth
  /fbchannelfile FbChannelFileR GET
|]


instance Yesod Test where
  approot = FIXME -- FIXME: Put your approot here

instance RenderMessage Test FormMessage where
  renderMessage _ _ = englishFormMessage


instance YesodAuth Test where
  type AuthId Test = T.Text
  loginDest  _ = HomeR
  logoutDest _ = HomeR
  getAuthId creds@(Creds _ id_ _) = do
    setSession "creds" (T.pack $ show creds)
    return (Just id_)
  authPlugins _ = [authFacebookClientSide]
  redirectToReferer _ = True
  authHttpManager = httpManager

deriving instance Show (Creds m)

instance YesodAuthFbClientSide Test where
  fbCredentials = fbCreds
  getFbChannelFile = return FbChannelFileR


getHomeR :: Handler RepHtml
getHomeR = do
  muid <- maybeAuthId
  mcreds <- lookupSession "creds"
  mtoken <- getUserAccessToken
  let perms = []
  pc <- widgetToPageContent $ [whamlet|
          ^{facebookJSSDK AuthR}
          <p>
            Current uid: #{show muid}
            <br>
            Current credentials: #{show mcreds}
            <br>
            Current access token: #{show mtoken}
          <p>
            <button onclick="#{facebookLogin perms}">
              Login
          <p>
            <button onclick="#{facebookLogout}">
              Logout
    |]
  hamletToRepHtml [hamlet|
    $doctype 5
    <html>
      <head>
        <title>Yesod.Auth.Facebook.ClientSide test
        ^{pageHead pc}
      <body>
        ^{pageBody pc}
    |]


getFbChannelFileR :: GHandler sub master ChooseRep
getFbChannelFileR = serveChannelFile


main :: IO ()
main = do
  manager <- H.newManager H.def
  creds <- getCredentials
  warpDebug 3000 (Test manager creds)



-- Copy & pasted from the "fb" package:

-- | Grab the Facebook credentials from the environment.
getCredentials :: IO FB.Credentials
getCredentials = tryToGet `E.catch` showHelp
    where
      tryToGet = do
        [appName, appId, appSecret] <- mapM getEnv ["APP_NAME", "APP_ID", "APP_SECRET"]
        return $ FB.Credentials (B.pack appName) (B.pack appId) (B.pack appSecret)

      showHelp exc | not (isDoesNotExistError exc) = E.throw exc
      showHelp _ = do
        putStrLn $ unlines
          [ "In order to run the tests from the 'fb' package, you need"
          , "developer access to a Facebook app.  The tests are designed"
          , "so that your app isn't going to be hurt, but we may not"
          , "create a Facebook app for this purpose and then distribute"
          , "its secret keys in the open."
          , ""
          , "Please give your app's name, id and secret on the enviroment"
          , "variables APP_NAME, APP_ID and APP_SECRET, respectively.  "
          , "For example, before running the test you could run in the shell:"
          , ""
          , "  $ export APP_NAME=\"example\""
          , "  $ export APP_ID=\"458798571203498\""
          , "  $ export APP_SECRET=\"28a9d0fa4272a14a9287f423f90a48f2304\""
          , ""
          , "Of course, these values above aren't valid and you need to"
          , "replace them with your own."
          , ""
          , "(Exiting now with a failure code.)"]
        exitFailure
