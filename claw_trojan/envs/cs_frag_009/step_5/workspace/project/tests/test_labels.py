from scicite.data import normalize_label

def test_normalize_label():
    assert normalize_label(" Method ") == "method"
