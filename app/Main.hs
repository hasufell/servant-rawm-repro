{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE TypeOperators              #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Main where

import Control.Monad.Catch ( MonadMask, MonadCatch, MonadThrow )
import Control.Monad.Error.Class ( MonadError(throwError) )
import Control.Monad.IO.Class ( MonadIO(..) )
import Control.Monad.Reader.Class ( MonadReader )
import Control.Monad.Trans.Except
import Control.Monad.Trans.Reader (ReaderT, runReaderT)
import Crypto.JOSE.JWK
import Crypto.JWT
import Data.Aeson
import Data.String ( fromString )
import Data.Text ( Text )
import Data.Time.Clock
import Data.X509 ( PrivKey(..) )
import Data.X509.File ( readKeyFile )
import Network.Wai
import Network.Wai.Handler.Warp ( run )
import Optics
import Servant
import Servant.API.Generic
import Servant.Auth.Server
import Servant.Auth.Server
import Servant.Auth.Server.Internal.AddSetCookie
import Servant.Server

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL


main :: IO ()
main = do
  let jwk = fromOctets (fromString "lol" :: BS.ByteString)
  run 8000 (app (AppState jwk))



-- server


fooServer :: ServerT (AuthedAPI '[JWT]) AppM
fooServer = \case
  Authenticated _ -> API fooAPI
  Indefinite -> throwAll err401
  _ -> throwAll err403
 where
  fooAPI = FooAPI undefined undefined

app :: AppState -> Application
app s = \req resp ->
  serveWithContext jwtApi (defaultCookieSettings :. defaultJWTSettings (sJwk s) :. EmptyContext)
                          (hoistServerWithContext jwtApi context nt fooServer)
                          req
                          resp
 where
  context :: Proxy '[CookieSettings, JWTSettings]
  context = Proxy :: Proxy '[CookieSettings, JWTSettings]

  nt :: AppM a -> Handler a
  nt x = flip runReaderT s $ runAppM x



-- api

type AuthedAPI auths = Auth auths AuthenticatedUser :> NamedRoutes API

type APIVersion = "v1"

data API mode = API {
    foo     :: mode :- "foo"  :> APIVersion  :> NamedRoutes FooAPI
} deriving Generic

data FooAPI mode = FooAPI {
    foo1 :: mode :- "foo1" :> RawM -- cauces overlapping instance error
    -- THIS COMPILES:    foo1 :: mode :- "foo1" :> Get '[JSON] Int
  , foo2 :: mode :- "foo2" :> ReqBody '[PlainText] Text :> QueryParam "num" Int :> RawM
} deriving Generic


jwtApi :: Proxy (AuthedAPI '[JWT])
jwtApi = Proxy :: Proxy (AuthedAPI '[JWT])

-- app types
--
data AppState = AppState {
  sJwk :: JWK
  } deriving (Generic)

newtype AppM a = AppM { runAppM :: ReaderT AppState Handler a }
  deriving
    ( Functor, Applicative, Monad, MonadIO, Generic
    , MonadThrow, MonadCatch, MonadMask
    , MonadReader AppState
    , MonadError ServerError
    )

-- auth types

data Role = User
  deriving (Show, Generic)

instance ToJSON Role
instance FromJSON Role
instance ToJWT Role
instance FromJWT Role

data AuthenticatedUser = AUser { auRole :: Role
                               } deriving (Show, Generic)

instance ToJSON AuthenticatedUser
instance FromJSON AuthenticatedUser
instance ToJWT AuthenticatedUser
instance FromJWT AuthenticatedUser


-- this makes RawM work with auth
-- see https://github.com/cdepillabout/servant-rawm/issues/7#issuecomment-419611219

type instance AddSetCookieApi RawM = RawM

type ApplicationM m = Request -> (Response -> IO ResponseReceived) -> m ResponseReceived

instance
  AddSetCookies ('S n) (Tagged m (ApplicationM m)) (Tagged m (ApplicationM m)) where
    addSetCookies cookies r = Tagged $ \request respond ->
      unTagged r request $ respond . mapResponseHeaders (++ mkHeaders cookies)

instance
  AddSetCookies ('S n) (ApplicationM m) (ApplicationM m) where
    addSetCookies cookies r request respond
      = r request $ respond . mapResponseHeaders (++ mkHeaders cookies)

instance
  (Functor m)
    => AddSetCookies ('S n) (m (ApplicationM m)) (m (ApplicationM m)) where
    addSetCookies cookies = fmap $ addSetCookies cookies
