package com.ocadotechnology.sttp.oauth2.backend

import cats.Monad
import cats.effect.Clock
import cats.effect.Concurrent
import cats.implicits._
import com.ocadotechnology.sttp.oauth2.AccessTokenProvider
import com.ocadotechnology.sttp.oauth2.Secret
import com.ocadotechnology.sttp.oauth2.common.Scope
import eu.timepit.refined.types.string.NonEmptyString
import sttp.capabilities.Effect
import sttp.client3._
import sttp.model.Uri

import com.ocadotechnology.sttp.oauth2.cache.ce2.CachingAccessTokenProvider
import com.ocadotechnology.sttp.oauth2.cache.ce2.CachingAccessTokenProvider._
import com.ocadotechnology.sttp.oauth2.cache.ce2.CatsRefExpiringCache
import com.ocadotechnology.sttp.oauth2.cache.ExpiringCache

// TODO move tests (or rather write simpler tests, because caching is tested separately)

/**
  * Sttp backend, that adds access token in bearer header to every outgoing request
  */
final class SttpOauth2ClientCredentialsCatsBackend[F[_]: Monad, P] private (
  delegate: SttpBackend[F, P],
  cachingAccessTokenProvider: CachingAccessTokenProvider[F],
  scope: Scope
) extends DelegateSttpBackend(delegate) {

  override def send[T, R >: P with Effect[F]](request: Request[T, R]): F[Response[T]] = for {
    token    <- cachingAccessTokenProvider.requestToken(scope)
    response <- delegate.send(request.auth.bearer(token.accessToken.value))
  } yield response

}

object SttpOauth2ClientCredentialsCatsBackend {

  /**
    * Create default instance with CatsRefExpiringCache
    */
  def apply[F[_]: Concurrent: Clock, P](
    tokenUrl: Uri,
    clientId: NonEmptyString,
    clientSecret: Secret[String]
  )(
    scope: Scope
  )(
    implicit backend: SttpBackend[F, P]
  ): F[SttpOauth2ClientCredentialsCatsBackend[F, P]] = {
    val accessTokenProvider = AccessTokenProvider.instance(tokenUrl, clientId, clientSecret)
    usingAccessTokenProvider(accessTokenProvider)(scope)
  }

  /** Keep in mind that the given implicit `backend` may be different than this one used by `accessTokenProvider`
    */
  def usingAccessTokenProvider[F[_]: Concurrent: Clock, P](
    accessTokenProvider: AccessTokenProvider[F]
  )(
    scope: Scope
  )(
    implicit backend: SttpBackend[F, P]
  ): F[SttpOauth2ClientCredentialsCatsBackend[F, P]] =
    CatsRefExpiringCache[F, Scope, TokenWithExpirationTime].flatMap(usingAccessTokenProviderAndCache(accessTokenProvider, _)(scope))

  def usingCache[F[_]: Concurrent: Clock, P](
    cache: ExpiringCache[F, Scope, TokenWithExpirationTime]
  )(
    tokenUrl: Uri,
    clientId: NonEmptyString,
    clientSecret: Secret[String]
  )(
    scope: Scope
  )(
    implicit backend: SttpBackend[F, P]
  ): F[SttpOauth2ClientCredentialsCatsBackend[F, P]] = {
    val accessTokenProvider = AccessTokenProvider.instance(tokenUrl, clientId, clientSecret)
    usingAccessTokenProviderAndCache(accessTokenProvider, cache)(scope)
  }

  /** Keep in mind that the given implicit `backend` may be different than this one used by `accessTokenProvider`
    */
  def usingAccessTokenProviderAndCache[F[_]: Concurrent: Clock, P](
    accessTokenProvider: AccessTokenProvider[F],
    cache: ExpiringCache[F, Scope, TokenWithExpirationTime]
  )(
    scope: Scope
  )(
    implicit backend: SttpBackend[F, P]
  ): F[SttpOauth2ClientCredentialsCatsBackend[F, P]] =
    CachingAccessTokenProvider.instance[F](accessTokenProvider, cache).map(new SttpOauth2ClientCredentialsCatsBackend(backend, _, scope))
    
  

}
