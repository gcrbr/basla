# basla
![python 3.x](https://img.shields.io/static/v1?label=python&message=3.x&color=blue)

Python module that allows Tor to be used for sockets and HTTP requests

## Installation
To install basla, clone the repository content and run the following command:
```console
$ python3 setup.py install
```

If you do not have Tor yet (not Tor browser!), follow the [official guide](https://community.torproject.org/onion-services/setup/install/) to install it, or [download the expert bundle](https://www.torproject.org/download/tor/) from the official website.

NOTE: If you download the expert bundle manually, you will have to link the path to the Tor binary when using basla
```python
import basla
tor  = basla.Tor('/path/to/tor')
```
Either way, you can just leave it blank.

## Usage
To use basla you have to bind it to the `socket` library:
```python
import basla
import socket

tor = basla.Tor()
tor.bind(socket)
```

Any connection made through the socket library will be proxied through Tor from now on.

It is enough to make it work for `requests`, `urllib`, `httpx`, etc.


You can also use the proxy manually, without binding:

```python
import basla
import requests

tor = basla.Tor()
session = requests.session()
session.proxies = {
    'https': tor.get_formatted_proxy()
}
```

For full examples, please take a look at the [examples](examples) folder.