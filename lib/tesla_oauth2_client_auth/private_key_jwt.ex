defmodule TeslaOAuth2ClientAuth.PrivateKeyJWT do
  @moduledoc """
  Tesla middleware that implements the `"private_key_jwt"` authentication scheme for
  [https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication](OpenID Connect clients)

  The client configuration must contain a `"jwks"` member whose value is a list of JWKs,
  including private keys. This middleware will sign the JWTs with the first encryption key
  found that conforms to the `:jwt_sig_alg` option.

  The options of this middleware are:
  - `:jwt_lifetime`: the lifetime of the JWT in seconds. Defaults to `30`
  - `:jwt_sig_alg`: the algorithm(s) to sign the JWTs. Defaults to `"RS256"`
  - `:jwt_jti_callback`: a `(TeslaOAuth2ClientAuth.opts() -> String.t())` function that returns
  the `"jti"` field of the JWT. Defaults to a random 16-bytes base64 encoded string
  - `:jwt_additional_claims`: claims added to the JWT. They have precedence over the default
  claims
  """

  @behaviour Tesla.Middleware

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  @impl true
  def call(%Tesla.Env{body: %{}} = env, next, opts) do
    client_id = opts[:client_id] || raise "Missing client id"

    body =
      env.body
      |> Map.put("client_id", client_id)
      |> Map.put("client_assertion_type", @assertion_type)
      |> Map.put("client_assertion", build_assertion(opts))

    %Tesla.Env{env | body: body}
    |> Tesla.run(next)
  end

  defp build_assertion(opts) do
    client_id = opts[:client_id] || raise "Missing client id"
    jwks = opts[:client_config]["jwks"]["keys"] || raise "Missing jwks`"
    issuer = opts[:server_metadata]["token_endpoint"] ||
      raise "Missing token endpoint to be used as the audience from server metadata"
    lifetime = opts[:jwt_lifetime] || 30
    sig_alg = opts[:jwt_sig_alg] || "RS256"

    jti =
      case opts[:jwt_jti_callback] do
        callback when is_function(callback, 1) ->
          callback.(opts)

        nil ->
          gen_jti()
      end

    message =
      %{
        iss: client_id,
        sub: client_id,
        aud: issuer,
        jti: jti,
        exp: now() + lifetime,
        iat: now()
      }
      |> Map.merge(opts[:jwt_additional_claims] || %{})
      |> Jason.encode!()

    signature_key(jwks, sig_alg)
    |> JOSE.JWK.from_map()
    |> JOSE.JWS.sign(message, %{"alg" => sig_alg})
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp signature_key(jwks, sig_alg) do
    case JOSEUtils.JWKS.signature_keys(jwks, sig_alg) do
      [jwk | _] ->
        jwk

      _ ->
        raise "No suitable signature key found in client's `jwks`"
    end
  end

  defp gen_jti(), do: :crypto.strong_rand_bytes(16) |> Base.encode64(padding: false)

  defp now(), do: System.system_time(:second)
end
