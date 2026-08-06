<?php

declare(strict_types=1);

namespace Ronu\AppContext\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Ronu\AppContext\Context\AppContext;

/**
 * Mints JWTs bound to an application context.
 *
 * This package already enforces a claim contract on the way in: JwtVerifier
 * requires `aud`, `iss` and `sub`; AuthenticateChannel matches `aud` against the
 * resolved channel; EnforceContextBinding matches `tid` and `did`. Until this
 * contract existed the minting side was left to each consuming application,
 * so every host had to re-derive the same claim set by hand — and any drift
 * between the two sides produces tokens that authenticate nowhere.
 *
 * Implementations are the authoritative source for that claim set.
 */
interface ContextTokenIssuerInterface
{
    /**
     * Build the access token + refresh token pair for a user in a context.
     *
     * The `token` and `access_token` keys carry the same value: `token` is the
     * php-open-source-saver/jwt-auth convention, `access_token` is the name
     * RFC 6749 §5.1 gives it. Both are emitted so consumers of either
     * convention work unchanged.
     *
     * @return array{
     *     token: string,
     *     access_token: string,
     *     token_type: string,
     *     expires_in: int,
     *     refresh_token: string,
     *     refresh_expires_in: int
     * }
     */
    public function issueFor(Authenticatable $user, AppContext $context, ?Request $request = null): array;

    /**
     * Claims that bind an access token to the given context.
     *
     * Exposed separately so callers that mint a token themselves — a refresh
     * endpoint rotating an access token, for instance — bind it with exactly
     * the same claims as a fresh login.
     *
     * @return array{iss: string, aud: string|null, tid: string|null, did: string|null}
     */
    public function accessClaims(AppContext $context, Authenticatable $user, ?Request $request = null): array;
}
