import argparse
import urlparse
import flask
from gevent.wsgi import WSGIServer
import json
import os
import potr


class Account(potr.context.Account):
    def loadPrivkey(self):
        return None

    def savePrivkey(self):
        pass


class Context(potr.context.Context):
    def __init__(self, *args, **kwargs):
        self.out = []
        super(Context, self).__init__(*args, **kwargs)

    def inject(self, fragment, appdata):
        self.out.append(str(fragment))


# Create a fresh account and get a key
alice = Account('alice', None, None)
ctx = Context(alice, 'bob')
ctx.authStartV2()


def testA():
    # FIXME What is supposed to be passed to POTR?
    return str(ctx.out[0])


app = flask.Flask(__name__, static_folder='../docs', static_path='')
app.debug=True


@app.route('/')
def index(**kwargs):
    return flask.redirect('/index.html')


@app.route('/info')
def info(**kwargs):
    d = {}
    d['potr-version'] = potr.VERSION
    # Add more info here as necessary
    return flask.jsonify(d)


@app.route('/rpc', methods=['POST'])
def post_rpc(**kwargs):
    methods = {'testA': testA,
               }
    method = flask.request.form['method']
    if method in methods:
        d = methods[method]()
        return flask.jsonify({'result': d})


if __name__ == '__main__':
    parser = argparse.ArgumentParser('otrjs debug server')
    parser.add_argument('--port', type=int, default=8090)
    ARGS = parser.parse_args()

    print 'Serving on port', ARGS.port
    if app.debug:
        # Run the regular server (with reloading and debugging)
        app.run('0.0.0.0', ARGS.port)
    else:
        # Run the fast gevent server
        http_server = WSGIServer(('', ARGS.port), app)
        http_server.serve_forever()
