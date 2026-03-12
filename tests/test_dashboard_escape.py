from __future__ import annotations

from exkururusoc.routers.sources_dashboard import SourceCreateRequest, create_source, soc_dashboard


def test_dashboard_escapes_html_values(setup_env) -> None:
    source = SourceCreateRequest(
        source_id="xss-source",
        product_name="<script>alert(1)</script>",
        source_type="api",
        base_url="http://127.0.0.1:8811",
        auth_type="token",
        auth_secret_ref="xss-secret",
    )
    create_source(source, x_admin_token="test-admin-token")
    text = soc_dashboard(token=None, x_admin_token="test-admin-token")
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
