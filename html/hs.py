import os
import shutil
import functools
from stem import StreamStatus
from stem.control import EventType, Controller
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route('/')
@app.route('/index')
def index():
  print('[!] IP : %s' % request.remote_addr)
  stream_listener = functools.partial(stream_event, controller)
  controller.add_event_listener(stream_listener, EventType.STREAM)
  return render_template('index.html')

def stream_event(controller, event):
  if event.status == StreamStatus.SUCCEEDED and event.circ_id:
    circ = controller.get_circuit(event.circ_id)

    exit_fingerprint = circ.path[-1][0]
    exit_relay = controller.get_network_status(exit_fingerprint)

    print("Exit relay for our connection to %s" % (event.target))
    print("  address: %s:%i" % (exit_relay.address, exit_relay.or_port))
    print("  fingerprint: %s" % exit_relay.fingerprint)
    print("  nickname: %s" % exit_relay.nickname)
    print("  locale: %s" % controller.get_info("ip-to-country/%s" % exit_relay.address, 'unknown'))
    print("")

print(' [*] Connecting to tor')

with Controller.from_port() as controller:
  controller.authenticate()

  # All hidden services have a directory on disk. Lets put ours in tor's data
  # directory.
  hidden_service_dir = os.path.join(controller.get_conf('DataDirectory', 'tmp/tmp'), 'darkweb')

  # Create a hidden service where visitors of port 80 get redirected to local
  # port 5000 (this is where Flask runs by default).
  print(" [*] Creating to the hidden service in %s" % hidden_service_dir)
  result = controller.create_hidden_service(hidden_service_dir, 80, target_port = 5000)

  # The hostname is only available when we can read the hidden service
  # directory. This requires us to be running with the same user as tor.
  if result.hostname:
    print(" [*] Our service is available at %s, press ctrl+c to quit" % result.hostname)

  else:
    print(" [*] Unable to determine our service's hostname, probably due to being unable to read the hidden service directory")

  try:
    app.run()
  finally:

    # Shut down the hidden service and clean it off disk. Note that you *don't*
    # want to delete the hidden service directory if you'd like to have this
    # same *.onion address in the future.
    print(" * Shutting down our hidden service")
    controller.remove_hidden_service(hidden_service_dir)
    shutil.rmtree(hidden_service_dir)
