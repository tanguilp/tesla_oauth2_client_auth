defmodule TeslaOAuth2ClientAuth do
  @moduledoc """
  Tesla middlewares for OAuth2 and OpenID Connect client authentication

  ## Support

  |Method|Implementation|Protocol|
  |:----:|--------------|:------:|
  |none|`TeslaOAuth2ClientAuth.None`|OAuth2|
  |client_secret_basic|`TeslaOAuth2ClientAuth.ClientSecretBasic`|OAuth2|
  |client_secret_post|`TeslaOAuth2ClientAuth.ClientSecretPost`|OAuth2|
  |client_secret_jwt|`TeslaOAuth2ClientAuth.ClientSecretJWT`|OpenID Connect|
  |private_key_jwt|`TeslaOAuth2ClientAuth.PrivateKeyJWT`|OpenID Connect|

  Note that `Tesla` does not support modifying TLS parameters in middlewares, which is
  why `"tls_client_auth"` and `"self_signed_tls_client_auth"` are unsupported.

  ## Options
  A `TeslaOAuth2ClientAuth` middleware receives a `t:opts/0` as an option, which contains:
  - the client id (`:client_id`), mandatory
  - the client configuration (`:client_config`, see `t:client_config/0`)
  - the OAuth2 or OpenID Connect server metadata (`:server_metadata`)
  - any other option as documented by the implementations
  """

  defmodule UnsupportedClientAuthenticationMethod do
    defexception [:requested_method]

    @type t :: %__MODULE__{
            requested_method: String.t() | nil
          }

    @impl true
    def message(%{requested_method: nil}) do
      "no authentication method set"
    end

    def message(%{requested_method: requested_method}) do
      "unsupported authentication method `#{requested_method}`"
    end
  end

  @type opts :: [opt]

  @type opt ::
          {:client_id, client_config}
          | {:client_config, client_config}
          | {:server_metadata, %{optional(String.t()) => any()}}
          | {atom(), any()}

  @typedoc """
  Client configuration is a map whose keys are those documented in
  [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata).

  In addition, other keys can be used by specific implementations. For instance,
  `"client_secret_basic"` uses the `"client_secret"`.
  """
  @type client_config :: %{optional(String.t()) => any()}

  @doc """
  Returns the #{__MODULE__} middleware for client authentication from client configuration
  (using the `"token_endpoint_auth_method"` configuration field) or an authentication method
  string

  If unknown, raises an `#{__MODULE__}.UnsupportedClientAuthenticationMethod` exception.
  """
  @spec middleware!(client_config() | String.t()) :: module() | no_return()
  def middleware!(%{} = config), do: middleware!(config["token_endpoint_auth_method"])
  def middleware!("client_secret_basic"), do: TeslaOAuth2ClientAuth.ClientSecretBasic
  def middleware!("client_secret_post"), do: TeslaOAuth2ClientAuth.ClientSecretPost
  def middleware!("none"), do: TeslaOAuth2ClientAuth.None

  def middleware!(unknown),
    do: raise(UnsupportedClientAuthenticationMethod, requested_method: unknown)
end
