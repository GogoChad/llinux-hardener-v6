def test_api_module_imports():
    import hardener.api
    assert hardener.api.app.title == "Linux Hardener API"
