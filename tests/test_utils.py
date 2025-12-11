from nmap_gui.utils import slugify_filename_component


def test_slugify_replaces_disallowed_characters():
    assert slugify_filename_component("prod server #1") == "prod_server_1"


def test_slugify_trims_separators_and_limits_length():
    long_value = "--example--" + ("a" * 120)
    result = slugify_filename_component(long_value)
    assert result.startswith("example")
    assert len(result) == 80


def test_slugify_uses_fallback_when_empty():
    assert slugify_filename_component("@@@", fallback="target") == "target"
