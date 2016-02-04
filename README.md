# openssl

[http://wiki.call-cc.org/eggref/4/openssl](http://wiki.call-cc.org/eggref/4/openssl)

tcpのportをsslに変換する方法がなかったので足した。

`(tcp-ports->ssl-ports tcp-in tcp-out [(ctx <symbol>)])`

