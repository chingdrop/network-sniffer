from scapy_endpoint.main import ScapyEndpointTest


class MyTestApp(ScapyEndpointTest):
    class Meta:
        argv = []
        config_files = []

class MyTestCase:
    app_class = MyTestApp

    def test_scapy_endpoint():
        # test scapy_endpoint without any subcommands or arguments
        with ScapyEndpointTest() as app:
            app.run()
            assert app.exit_code == 0

    def test_scapy_endpoint_debug():
        # test that debug mode is functional
        argv = ['--debug']
        with ScapyEndpointTest(argv=argv) as app:
            app.run()
            assert app.debug is True

    def test_quick_enumeration(self):
        argv = ['quick_enumeration', 'eth0']
        with ScapyEndpointTest(argv=argv) as app:
            result = app.run()
            assert isinstance(result, list)
            assert 0 <= len(result) 
