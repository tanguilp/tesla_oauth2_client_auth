defmodule TeslaOAuth2ClientAuthTest.ClientSecretJWT do
  use ExUnit.Case

  alias TeslaOAuth2ClientAuth.ClientSecretJWT

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  test "valid request using client's secret" do
    client =
      Tesla.client(
        [
          {ClientSecretJWT,
           %{
             client_config: client_config("client1"),
             server_metadata: server_metadata()
           }}
        ],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.post(client, "/", %{})
    assert result.body["client_assertion_type"] == @assertion_type

    assertion = result.body["client_assertion"]

    jwk =
      JOSE.JWK.from(%{
        "kty" => "oct",
        "k" => Base.encode64(client_config("client1")["client_secret"])
      })

    assert {true, content, _} = JOSE.JWS.verify_strict(jwk, ["HS256"], assertion)

    content = Jason.decode!(content)

    assert content["iss"] == "client1"
    assert content["sub"] == "client1"
    assert content["aud"] == server_metadata()["token_endpoint"]
    assert is_integer(content["exp"])
    assert is_integer(content["iat"])
    assert is_binary(content["jti"])
  end

  test "valid request using client's JWKs" do
    client =
      Tesla.client(
        [
          {ClientSecretJWT,
           %{
             client_config: client_config("client2"),
             server_metadata: server_metadata()
           }}
        ],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.post(client, "/", %{})
    assert result.body["client_assertion_type"] == @assertion_type

    assertion = result.body["client_assertion"]

    jwk = client_config("client2")["jwks"]["keys"] |> List.first() |> JOSE.JWK.from_map()

    assert {true, content, _} = JOSE.JWS.verify_strict(jwk, ["HS256"], assertion)

    content = Jason.decode!(content)

    assert content["iss"] == "client2"
    assert content["sub"] == "client2"
    assert content["aud"] == server_metadata()["token_endpoint"]
    assert is_integer(content["exp"])
    assert is_integer(content["iat"])
    assert is_binary(content["jti"])
  end

  test "jti callback is called" do
    client =
      Tesla.client(
        [
          {ClientSecretJWT,
           %{
             client_config: client_config("client1"),
             server_metadata: server_metadata(),
             jwt_jti_callback: &TeslaOAuth2ClientAuthTest.Callback.jti_callback/1
           }}
        ],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.post(client, "/", %{})

    assertion = result.body["client_assertion"]

    jwk =
      JOSE.JWK.from(%{
        "kty" => "oct",
        "k" => Base.encode64(client_config("client1")["client_secret"])
      })

    assert {true, content, _} = JOSE.JWS.verify_strict(jwk, ["HS256"], assertion)

    content = Jason.decode!(content)

    assert content["jti"] == "some_generated_jti"
  end

  test "additional claims are added" do
    client =
      Tesla.client(
        [
          {ClientSecretJWT,
           %{
             client_config: client_config("client1"),
             server_metadata: server_metadata(),
             jwt_additional_claims: %{"some_claim" => "some_value"}
           }}
        ],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.post(client, "/", %{})

    assertion = result.body["client_assertion"]

    jwk =
      JOSE.JWK.from(%{
        "kty" => "oct",
        "k" => Base.encode64(client_config("client1")["client_secret"])
      })

    assert {true, content, _} = JOSE.JWS.verify_strict(jwk, ["HS256"], assertion)

    content = Jason.decode!(content)

    assert content["some_claim"] == "some_value"
  end

  test "valid request using client's secret and HS512 MAC alg" do
    client =
      Tesla.client(
        [
          {ClientSecretJWT,
           %{
             client_config: client_config("client3"),
             server_metadata: server_metadata()
           }}
        ],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.post(client, "/", %{})
    assert result.body["client_assertion_type"] == @assertion_type

    assertion = result.body["client_assertion"]

    jwk =
      JOSE.JWK.from(%{
        "kty" => "oct",
        "k" => Base.encode64(client_config("client3")["client_secret"])
      })

    assert {true, content, _} = JOSE.JWS.verify_strict(jwk, ["HS512"], assertion)

    content = Jason.decode!(content)

    assert content["iss"] == "client3"
    assert content["sub"] == "client3"
    assert content["aud"] == server_metadata()["token_endpoint"]
    assert is_integer(content["exp"])
    assert is_integer(content["iat"])
    assert is_binary(content["jti"])
  end

  test "raises on missing client id" do
    client =
      Tesla.client(
        [{ClientSecretJWT, %{client_config: client_config("client1")}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.post(client, "/", %{})
    end
  end

  test "raises on missing client config key" do
    client =
      Tesla.client(
        [{ClientSecretJWT, %{}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.post(client, "/", %{})
    end
  end

  test "raises on missing client config data" do
    client =
      Tesla.client(
        [{ClientSecretJWT, %{client_config: %{}}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.post(client, "/", %{})
    end
  end

  defp client_config("client1") do
    %{
      "client_id" => "client1",
      "token_endpoint_auth_signing_alg" => "HS256",
      "client_secret" => "some secret"
    }
  end

  defp client_config("client2") do
    %{
      "client_id" => "client2",
      "token_endpoint_auth_signing_alg" => "HS256",
      "jwks" => %{
        "keys" => [
          %{"k" => "vbGfJodzovvNvtZ9W2uMlw", "kty" => "oct"}
        ]
      }
    }
  end

  defp client_config("client3") do
    %{
      "client_id" => "client3",
      "token_endpoint_auth_signing_alg" => "HS512",
      "client_secret" => "some other secret"
    }
  end

  defp server_metadata() do
    %{
      "token_endpoint" => "https://www.example.com/auth/token",
      "token_endpoint_auth_signing_alg_values_supported" => ["HS256", "HS512"]
    }
  end
end
