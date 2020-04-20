defmodule TeslaOAuth2ClientAuth do
  @moduledoc """
  [Tesla](https://github.com/teamon/tesla) middlewares for OAuth2 and OpenID Connect client
  authentication

  ## Support

  |          Method         |                Implementation             | Protocol       |
  |:-----------------------:|:-----------------------------------------:|:--------------:|
  | `"none"`                | `TeslaOAuth2ClientAuth.None`              | OAuth2         |
  | `"client_secret_basic"` | `TeslaOAuth2ClientAuth.ClientSecretBasic` | OAuth2         |
  | `"client_secret_post"`  | `TeslaOAuth2ClientAuth.ClientSecretPost`  | OAuth2         |
  | `"client_secret_jwt"`   | `TeslaOAuth2ClientAuth.ClientSecretJWT`   | OpenID Connect |
  | `"private_key_jwt"`     | `TeslaOAuth2ClientAuth.PrivateKeyJWT`     | OpenID Connect |

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
      "no authentication method set in client configuration"
    end

    def message(%{requested_method: requested_method}) do
      "unsupported authentication method `#{requested_method}`"
    end
  end

  @type opts :: %{
          required(:client_id) => String.t(),
          required(:client_config) => client_config(),
          required(:server_metadata) => server_metadata(),
          optional(atom()) => any()
        }

  @typedoc """
  Client configuration is a map whose keys are those documented in
  [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata).
  """
  @type client_config :: %{optional(String.t()) => any()}

  @typedoc """
  OAuth2 or OpenID Connect server metadata as documented in one of:
  - [OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html)
  - [OAuth 2.0 Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
  """
  @type server_metadata :: %{optional(String.t()) => any()}

  @doc """
  Returns the `#{__MODULE__}` middleware for client authentication from client configuration
  (using the `"token_endpoint_auth_method"` configuration field) or an authentication method
  string
  """
  @spec implementation(client_config() | (token_endpoint_auth_method :: String.t())) ::
          {:ok, module()} | {:error, UnsupportedClientAuthenticationMethod.t()}
  def implementation(%{} = config), do: implementation(config["token_endpoint_auth_method"])
  def implementation("client_secret_basic"), do: {:ok, TeslaOAuth2ClientAuth.ClientSecretBasic}
  def implementation("client_secret_post"), do: {:ok, TeslaOAuth2ClientAuth.ClientSecretPost}
  def implementation("client_secret_jwt"), do: {:ok, TeslaOAuth2ClientAuth.ClientSecretJWT}
  def implementation("private_key_jwt"), do: {:ok, TeslaOAuth2ClientAuth.PrivateKeyJWT}
  def implementation("none"), do: {:ok, TeslaOAuth2ClientAuth.None}

  def implementation(unknown),
    do: {:error, %UnsupportedClientAuthenticationMethod{requested_method: unknown}}

  @doc """
  Returns the `#{__MODULE__}` middleware for client authentication from client configuration
  (using the `"token_endpoint_auth_method"` configuration field) or an authentication method
  string
  """
  @spec implementation!(client_config() | (token_endpoint_auth_method :: String.t())) ::
          module() | no_return()
  def implementation!(conf_or_method) do
    case implementation(conf_or_method) do
      {:ok, impl} ->
        impl

      {:error, e} ->
        raise e
    end
  end
end
