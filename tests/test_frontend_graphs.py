from pathlib import Path


HTML = (Path(__file__).parents[1] / "index.html").read_text()


def test_tcptrace_graph_displays_ack_plus_window_and_ranges_it():
    assert "function ackWindowPoints(dataDir)" in HTML
    assert "name:'ACK+WIN'" in HTML
    assert "ACK+WIN %{y:,.0f}" in HTML
    assert "for(const p of ackWindowPoints(dir))vals.push(p.top)" in HTML


def test_plot_toolbar_replaces_reset_with_navigation_controls():
    config = HTML.split("const PLOT_CONFIG=", 1)[1].split(";", 1)[0]
    assert "resetScale2d" not in config
    for control in ("pan2d", "zoom2d", "zoomIn2d", "zoomOut2d", "autoScale2d", "toImage"):
        assert control in config
    assert "scrollZoom:true" in config
    assert "doubleClick:'autosize'" in config
