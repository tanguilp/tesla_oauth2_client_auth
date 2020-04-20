defmodule TeslaOAuth2ClientAuth.PrivateKeyJWT do
  @moduledoc """
  Tesla middleware that implements the `"private_key_jwt"` authentication scheme for
  [https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication](OpenID Connect clients)

  The client configuration must contain a `"jwks"` member whose value is a list of JWKs,
  including private keys. This middleware will sign the JWTs with the first encryption key
  found that conforms to the signature algorithm.

  To determine the signature algorithm to use, this middleware:
  - uses the client's `"token_endpoint_auth_signing_alg"` value if present, and check it against
  the server metadata `"token_endpoint_auth_signing_alg_values_supported"`
  - otherwise uses the `"token_endpoint_auth_signing_alg_values_supported"` server metadata and
  picks one algorithm that is suitable for signing
  - otherwise raises

  The options of this middleware are:
  - `:jwt_lifetime`: the lifetime of the JWT in seconds. Defaults to `30`
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

    issuer =
      opts[:server_metadata]["token_endpoint"] ||
        raise "Missing token endpoint to be used as the audience from server metadata"

    lifetime = opts[:jwt_lifetime] || 30
    sig_alg = sig_alg(opts[:client_config], opts[:server_metadata])

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

  defp sig_alg(client_config, server_metadata) do
    case client_config do
      %{"token_endpoint_auth_signing_alg" => "none"} ->
        raise "illegal `token_endpoint_auth_signing_alg` in client configuration: `none`"

      %{"token_endpoint_auth_signing_alg" => alg} ->
        if alg in (server_metadata["token_endpoint_auth_signing_alg_values_supported"] || []) do
          alg
        else
          raise "client's token endpoint auth algorithm not supported by the authorization server"
        end

      _ ->
        server_metadata["token_endpoint_auth_signing_alg_values_supported"]
        |> Enum.find(fn alg ->
          alg in [
            "Ed25519",
            "Ed448",
            "EdDSA",
            "ES256",
            "ES384",
            "ES512",
            "Poly1305",
            "PS256",
            "PS384",
            "PS512",
            "RS256",
            "RS384",
            "RS512"
          ]
        end)
        |> case do
          alg when is_binary(alg) ->
            alg

          nil ->
            raise "no suitable signature algorithm supported by the authorization server"
        end
    end
  end

  defp signature_key(jwks, sig_alg) do
    case JOSEUtils.JWKS.signature_keys(jwks, sig_alg) do
      [jwk | _] ->
        jwk

      _ ->
        raise "no suitable signature key found in client's `jwks`"
    end
  end

  defp gen_jti(), do: :crypto.strong_rand_bytes(16) |> Base.encode64(padding: false)

  defp now(), do: System.system_time(:second)
end
