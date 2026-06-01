defmodule GQL.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [finch_spec()]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: GQL.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Builds the `GQL.Finch` child spec, merging any pool configuration provided
  # by the host application. This is the only supported way to set transport
  # options (e.g. TLS opts), since `Finch.request/3` does not accept them.
  #
  # Example:
  #
  #     config :gql,
  #       finch_pools: %{
  #         default: [conn_opts: [transport_opts: [verify: :verify_none]]]
  #       }
  defp finch_spec do
    base = [name: GQL.Finch]

    case Application.get_env(:gql, :finch_pools) do
      nil -> {Finch, base}
      pools -> {Finch, Keyword.put(base, :pools, pools)}
    end
  end
end
