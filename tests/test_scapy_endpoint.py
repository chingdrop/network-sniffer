
from pytest import raises
from scapy_endpoint.main import ScapyEndpointTest

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


def test_command1():
    # test command1 without arguments
    argv = ['command1']
    with ScapyEndpointTest(argv=argv) as app:
        app.run()
        data,output = app.last_rendered
        assert data['foo'] == 'bar'
        assert output.find('Foo => bar')


    # test command1 with arguments
    argv = ['command1', '--foo', 'not-bar']
    with ScapyEndpointTest(argv=argv) as app:
        app.run()
        data,output = app.last_rendered
        assert data['foo'] == 'not-bar'
        assert output.find('Foo => not-bar')
