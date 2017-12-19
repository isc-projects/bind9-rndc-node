# BIND9 rndc for NodeJS

This module implements the BIND9 rndc management protocol and is
compatible with BIND 9.9 and later.

This is unsupported software and is provided without warranty.

## Example usage

The code below sends the "status" command to the default rndc port
on the machine `localhost`.   The key data is base64 encoded, as per
the usual `rndc.conf` syntax.

    var RNDC = require('./index');

    var key = '2or79WFROyibcP/qixhklCiZIL4aHfRIQj7yyodzQBw=';
    var algo = 'hmac-sha256';

    var session = RNDC.connect('localhost', 953, key, algo);

    session.on('ready', () => {
        session.send('status');
    });

    session.on('data', (obj) => {
        console.log(obj);
        session.end();
    });

    session.on('error', console.log);

Each call to `.send` sends a single command string to the server,
although with this module it is possible to maintain a persistent
connection to the rndc port and send multiple commands, achieving
higher throughput than is possible compared to opening a new rndc
connection for each command.

In BIND 9.11 and later a valid response will contain a `result`
key with a (string) variable containing the value `0`, or an error
code otherwise.
