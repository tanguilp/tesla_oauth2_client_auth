defmodule TeslaOAuth2ClientAuthTest.ClientSecretBasic do
  use ExUnit.Case

  alias TeslaOAuth2ClientAuth.ClientSecretBasic

  test "send request with valid credentials" do
    client =
      Tesla.client(
        [{ClientSecretBasic, %{client_config: client_config()}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert {:ok, result} = Tesla.get(client, "/")

    authz_header = Tesla.get_header(result, "authorization")

    assert authz_header == "Basic #{Base.encode64("client1:some secret")}"
  end

  test "raises on missing client id" do
    client =
      Tesla.client(
        [{ClientSecretBasic, %{client_config: Map.delete(client_config(), "client_id")}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.get(client, "/")
    end
  end

  test "raises on missing client config key" do
    client =
      Tesla.client(
        [{ClientSecretBasic, %{client_id: "client1"}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.get(client, "/")
    end
  end

  test "raises on missing client config data" do
    client =
      Tesla.client(
        [{ClientSecretBasic, %{client_config: %{}}}],
        TeslaOAuth2ClientAuthTest.Adapter
      )

    assert_raise RuntimeError, fn ->
      Tesla.get(client, "/")
    end
  end

  defp client_config() do
    %{
      "client_id" => "client1",
      "client_secret" => "some secret"
    }
  end
end
