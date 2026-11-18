"""Response wrapping against the real server."""

from __future__ import annotations

import pytest

import grow_openbao as sdk


def test_wrap_lookup_unwrap(client: sdk.OpenBaoClient) -> None:
    info = client.wrapping.wrap({"k": "v"}, 60)
    assert info.ttl_s == 60 and info.creation_path == "sys/wrapping/wrap"
    assert info.token.reveal() not in repr(info)
    look = client.wrapping.lookup_wrapping(info.token)
    assert look.creation_path == "sys/wrapping/wrap" and look.creation_ttl_s == 60
    out = client.wrapping.unwrap(info.token)
    assert out.data == {"k": "v"}
    with pytest.raises(sdk.ValidationError):
        client.wrapping.unwrap(info.token)
    with pytest.raises(sdk.ValidationError):
        client.wrapping.lookup_wrapping(info.token)


def test_wrapped_raw_request(client: sdk.OpenBaoClient) -> None:
    res = client.request("GET", "secret/data/sdk/allowed/hello", wrap_ttl_s=30)
    assert res.wrap_info is not None and res.data is None
    out = client.wrapping.unwrap(res.wrap_info.token)
    assert out.data is not None and out.data["data"] == {"value": "world"}
