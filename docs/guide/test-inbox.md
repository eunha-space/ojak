Testing with a temporary inbox
==============================

`ojak inbox` serves a temporary ActivityPub actor and prints a summary of each
inbox POST. Use it to check what an application delivers and whether Ojak
accepts the delivery. It uses the same authentication and dispatch path as
[an application inbox](./inbox.md).

From an Ojak checkout with mise installed, build the CLI and run it:

~~~~ sh
mise exec -- cargo build --locked -p ojak-cli
./target/debug/ojak inbox
~~~~

On macOS and Linux the command uses OpenSSH (`ssh` and `ssh-keygen`) to open a
public HTTPS tunnel. It tries Serveo, then Pinggy. Choose one with
`--tunnel-service serveo.net` or `--tunnel-service pinggy.io`. The listener
binds to `127.0.0.1` on port 3000 by default. Use `--port 0` to pick a free
port.

To bring your own tunnel or reverse proxy, pass its public HTTPS origin:

~~~~ sh
./target/debug/ojak inbox --url https://inbox.example.net --port 3000
~~~~

Forward that origin to `http://127.0.0.1:3000` and preserve the public `Host`
header and request path so HTTP signatures can verify. The origin must use
port 443 and have no path.

The command prints the handle at the assigned hostname and the actor and
inbox URLs. Look up the handle in your ActivityPub application and send it
an activity. For example, send a follow request from a test account to see
the `Follow` delivery. The actor observes requests without sending follow
acceptances or other activities.

Each inbox POST produces a JSON line with its HTTP status and dispatch
outcome. A dispatched activity includes its type, authenticated sender and
how Ojak established its authenticity. An activity that fails authentication
is marked `unverified`. Requests that never reach a listener can still return
202, for example when Ojak discards a repeat delivery.

A signed follow request can produce this summary:

~~~~ json
{"authentication":"Signature","outcome":"received","sender":"https://social.example/users/alice","status":202,"type":"Follow"}
~~~~

The command keeps up to 100 summaries in memory. Summaries omit request
bodies, signature headers and private keys. Press Ctrl-C to stop and discard
the session. Each run generates a new signing key, so use a fresh hostname
for another session when peers may have cached the previous actor's key.


Tunnelling an existing app
--------------------------

For an app already listening on a local port, run:

~~~~ sh
./target/debug/ojak tunnel 3000
~~~~

It prints the public HTTPS URL. Use `--tunnel-service` to choose a provider.
Configure your app to use that origin for its public URLs. Ctrl-C stops the
SSH connection and removes the temporary tunnel identity. If the provider
closes the connection, the command exits so a restart can establish a new
URL. Each connection uses pinned SSH host keys and a disposable client key.
