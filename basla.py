import subprocess
import socket
import atexit
import socks
import time
import os

class TorException(Exception):
    pass

class Tor:
    socks_port = 0
    control_port = 0
    control_password = None
    untouched_socket = (None, None)

    def __init__(self, tor_binary='tor'):
        '''
        Tor object

        **Parameters:**
        `tor_binary` (str): The path to the Tor binary file
        '''
        self.tor_binary = tor_binary
        self.run_tor()

    def gen_random_hashed_password(self) -> str:
        '''
        Generates a random password and hashes it with Tor

        **Returns:**
        str
        '''
        self.control_password = os.urandom(16).hex()
        return subprocess.check_output([self.tor_binary, '--hash-password', self.control_password]).decode().strip()

    def get_free_port(self) -> int:
        '''
        Finds a free TCP port

        **Returns:**
        int
        '''
        s = socket.socket()
        s.bind(('0.0.0.0', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def run_tor(self):
        '''
        Sets up and runs the Tor binary
        '''
        self.socks_port = self.get_free_port()
        self.control_port = self.get_free_port()
        try:
            self.tor = subprocess.Popen([
                self.tor_binary, 
                '-SocksPort', str(self.socks_port), 
                '-ControlPort', str(self.control_port),
                '-HashedControlPassword', self.gen_random_hashed_password()
            ], stdout=subprocess.PIPE)
        except Exception as e:
            raise TorException(f'Unable to run tor ({e})')
        self.check_process()
        atexit.register(lambda:self.tor.kill())

    def restart(self):
        '''
        Restarts the Tor process
        **NOTE:** Any previous bound created with `bind` will be lost
        '''
        self.tor.kill()
        self.run_tor()

    def check_process(self):
        '''
        Reads the process' stdout to find out whetever there are any errors and if the Tor control is ready.
        **NOTE:** Already called on `run_tor`
        '''
        line = ''
        while _ := self.tor.stdout.read(1):
            if _ != b'\n':
                line += _.decode()
            else:
                if '[err]' in line:
                    raise TorException(f'{line.split("[err] ")[1]}')
                if 'Opened Control listener connection' in line:
                    break
                line = ''

    def init_control(self) -> socket.socket:
        '''
        Creates a new socket for the Tor control protocol

        **Returns:**
        socket.socket
        '''
        control_socket = self.untouched_socket[0]()
        control_socket.connect(('127.0.0.1', self.control_port))
        control_socket.send(f'authenticate "{self.control_password}"\r\n'.encode())
        if control_socket.recv(1024).split()[0] == b'250':
            control_socket.send(b'setevents addrmap\r\n')
            control_socket.recv(8) # 250 OK
            return control_socket
        else:
            raise TorException('Unable to authenticate')

    def resolve(self, data: str, mode: int) -> str:
        '''
        Core function to `gethostbyname` and `gethostbyaddr`. Resolves an hostname to an ip address or vice-versa through Tor

        **Parameters:**
        `data` (str): The object to resolve, either an ip address or hostname
        `mode` (int): 1 for reverse (address->hostname), 0 for normal (hostname->address)

        **Returns:**
        str: The resolved object
        '''
        control = self.init_control()
        control.send(f'resolve {data}{" mode=reverse" if mode else ""}\r\n'.encode())
        control.recv(8) # 250 OK
        response = control.recv(2048)
        parts = response.split()
        control.close()
        if parts[:2] == [b'650', b'ADDRMAP']:
            if parts[3] == b'<error>':
                raise TorException(f'Unable to resolve \'{data}\'')
            return parts[3].decode()
        else:
            raise TorException(f'Unable to resolve \'{data}\'')

    def gethostbyname(self, hostname: str) -> str:
        '''
        Resolves ip address from an hostname through Tor

        **Parameters:**
        `hostname` (str): The hostname to resolve

        **Returns:**
        str: The resolved ip address
        '''
        return self.resolve(hostname, 0)

    def gethostbyaddr(self, address: str) -> str:
        '''
        Resolves hostname from an ip address through Tor

        **Parameters:**
        `address` (str): The ip address to resolve

        **Returns:**
        str: The resolved hostname
        '''
        return self.resolve(address, 1)

    def new_circuit(self):
        '''
        Creates a new circuit. In short, changes your exit ip address
        **NOTE:** This operation may be rate-limited for several seconds if done in a short time
        '''
        control = self.init_control()
        control.send(b'signal newnym\r\n')
        control.send(b'setevents guard notice\r\n')
        control.recv(8) # 250 OK
        if control.recv(8).split()[0] != b'250':
            control.close()
            raise TorException('Could not create new circuit')
        if notice := control.recv(1024).decode():
            if 'Rate limiting' in notice:
                time.sleep(int(notice.split('delaying by ')[1].split(' second')[0]))
            control.close()

    def get_proxy(self) -> tuple[str, int]:
        '''
        Returns the Tor proxy in a tuple

        **Returns:**
        (str, int): ip and port
        '''
        return ('127.0.0.1', self.socks_port)

    def get_formatted_proxy(self) -> str:
        '''
        Returns the Tor proxy in the <protocol>://<ip>:<port> format

        **Returns:**
        str
        '''
        return f'socks5://127.0.0.1:{self.socks_port}'

    def bind(self, module):
        '''
        Bind Tor to a module. Only supports the `socket` module currently (and all the ones that rely on it)

        **Parameters:**
        `module` (module): The module to bind Tor to
        '''
        if module.__name__ == 'socket':
            self.untouched_socket = (module.socket, module.getaddrinfo)
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, *self.get_proxy(), rdns=True)
            module.socket = socks.socksocket
            module.getaddrinfo = lambda *args:[(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]
        else:
            raise TorException('Invalid binding')