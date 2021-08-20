import pickle
import re
import socket
import threading
import traceback

from lib import Tree, Client, Packet


def handle(client_class):
    while True:
        try:
            message = client_class.socket.recv(4096)
            try:
                m_packet = pickle.loads(message)
            except EOFError:
                pass
            if re.match(r'^(.+) REQUESTS FOR CONNECTING TO NETWORK ON PORT (.+)$', m_packet.Data) is not None:
                match_obj = re.match(r'^(.+) REQUESTS FOR CONNECTING TO NETWORK ON PORT (.+)$', m_packet.Data)
                client_class.id = match_obj.group(1)
                client_class.port = int(match_obj.group(2))
                print(client_class.id)
                m_packet = Packet(
                    0, port, client_class.id, -1, f'CONNECT TO {client_class.parent.id} WITH PORT {client_class.parent.port}')
                client_class.socket.sendall(pickle.dumps(m_packet))
        except:
            traceback.print_exc()
            print(f"client {client_class.id} disconnected")
            client_class.socket.close()
            server.close()
            break


host = '127.0.0.1'
port = 23005

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))

server.listen()
print("Listening...")
myTree = Tree()

while True:
    try:
        client_socket, address = server.accept()

        c = Client(client_socket, address, 0, 0)
        parent = myTree.insert(c)
        c.parent = parent

        thread = threading.Thread(target=handle, args=(c,))
        thread.start()
    except:
        traceback.print_exc()
        server.close()
        break
