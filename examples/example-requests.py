import basla
import socket
import requests

# Create Tor object and bind it to socket
tor = basla.Tor('./tor')
tor.bind(socket)

# Current ip address
print('Current ip address', requests.get('https://icanhazip.com').text.strip())

# Example request to Z-Library
zlib = requests.get('http://zlibrary24tuxziyiyfr7zd46ytefdqbqd2axkmxm4o5374ptpc52fad.onion')
print('Z-Library response code', zlib.status_code)

# Changing ip address and getting it
tor.new_circuit()
print('New ip address', requests.get('https://icanhazip.com').text.strip())

# Resolving hostname
print('Github.com resolved address', tor.gethostbyname('github.com'))

# Restarting Tor
# NOTE: The bound must be done again
tor.restart()
tor.bind(socket)

# Getting the proxy for manual usage (unsupported modules?)
print('Proxy', *tor.get_proxy())
print('Formatted proxy', tor.get_formatted_proxy())