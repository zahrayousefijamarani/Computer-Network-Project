import pickle
import socket
import threading
import re
import time
import traceback
from typing import Pattern

from lib import FwTable, Packet, Child, Chat

# todo: add client to known_nodes every time we receive a packet

host = '127.0.0.1'
admin_port = 23005

my_server_port = 0

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, admin_port))
client.setblocking(True)
wait_for_answer = 0
user_id = ""
accepted = False
parent_id = 0
parent_port = 0

children = dict()
known_nodes = []

my_chat = None
in_chat = False
chat_names = []

fw_table = None
fw_blocked_chat = False
command = ""


def is_prev_id_parent(prev_id: str):
    return prev_id == parent_id


def add_to_known_nodes(c):
    global known_nodes
    for element in known_nodes:
        if element.id == c.id:
            return
    known_nodes.append(c)


def is_it_known(id):
    for element in known_nodes:
        if element.id == id:
            return True
    return False


def transfer_data(packet: Packet):
    global parent_id
    if not fw_table.does_packet_pass_fw(packet):
        print(
            f'Dropped packet with type {packet.Type} from {packet.SourceID} to {packet.DestinationID}.')
        # todo: more logging needed?
    elif str(packet.DestinationID) != "":
        prev_id = packet.PrevID
        dest_id = packet.DestinationID
        if dest_id == '-1':
            if parent_id != '-1' and parent_id != prev_id:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((host, parent_port))
                    s.sendall(pickle.dumps(Packet(
                        packet.Type, packet.SourceID, packet.DestinationID, user_id, packet.Data)))
                    s.close()
            for ch in children.keys():
                if ch.id != prev_id:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((host, ch.port))
                        s.sendall(pickle.dumps(Packet(
                            packet.Type, packet.SourceID, packet.DestinationID, user_id, packet.Data)))
                        s.close()
        else:
            for ch in children.keys():
                # if str(dest_id) == "4":
                #     print(dest_id)
                #     print(ch.id)
                #     print(children[ch])
                #     print("------")
                if ch.id == dest_id or children[ch].__contains__(dest_id):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((host, ch.port))
                        s.sendall(pickle.dumps(Packet(
                            packet.Type, packet.SourceID, packet.DestinationID, user_id, packet.Data)))
                        s.close()
                    return
            if parent_id != '-1':
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((host, parent_port))
                    s.sendall(pickle.dumps(Packet(
                        packet.Type, packet.SourceID, packet.DestinationID, user_id, packet.Data)))
                    s.close()
                return
            if parent_id == '-1':
                transfer_data(Packet(31, user_id, packet.SourceID, user_id,
                                     f'DESTINATION {packet.DestinationID} NOT FOUND.'))


def handle(socket):
    global user_id, children, my_server_port, \
        my_chat, in_chat, accepted, client, parent_id, \
        parent_port, my_server_port, host, admin_port, \
        known_nodes, chat_names, fw_table, fw_blocked_chat, wait_for_answer, command
    while True:
        try:
            message = socket.recv(4096)
            try:
                m_packet = pickle.loads(message)
            except EOFError:
                pass
            # Logging
            if m_packet.DestinationID != user_id and m_packet.DestinationID != -1 and not in_chat:
                m_packet.print_summary()
            # Firewall checking
            if not fw_table.does_packet_pass_fw(m_packet):
                print(
                    f'Dropped packet with type {m_packet.Type} from {m_packet.SourceID} to {m_packet.DestinationID}.')
                # todo: any more information and work to do?
                socket.close()
                return
            if str(m_packet.Type) == "41":  # Connection request
                c = Child(int(m_packet.Data), m_packet.SourceID)
                children[c] = []
                add_to_known_nodes(c)  # add child to known nodes
                if parent_id != '-1':
                    transfer_data(
                        Packet(20, c.id, parent_id, m_packet.PrevID, str(c.port)))
                socket.close()
                return
            if str(m_packet.Type) == '10':  # Routing request
                src_id = m_packet.SourceID
                dest_id = m_packet.DestinationID
                prev_id = m_packet.PrevID
                if dest_id == user_id:
                    transfer_data(
                        Packet(11, user_id, src_id, m_packet.PrevID, f'{user_id}'))
                else:
                    transfer_data(
                        Packet(10, src_id, dest_id, m_packet.PrevID, m_packet.Data))
                socket.close()
                return
            if str(m_packet.Type) == '11':  # Routing response
                src_id = m_packet.SourceID
                dest_id = m_packet.DestinationID
                prev_id = m_packet.PrevID
                if dest_id == user_id:
                    if is_prev_id_parent(prev_id):
                        print(f'{user_id}<-{m_packet.Data}')
                    else:
                        print(f'{user_id}->{m_packet.Data}')
                else:
                    if is_prev_id_parent(prev_id):
                        transfer_data(Packet(11, src_id, dest_id,
                                             m_packet.PrevID, f'{user_id}<-{m_packet.Data}'))
                    else:
                        transfer_data(Packet(11, src_id, dest_id,
                                             m_packet.PrevID, f'{user_id}->{m_packet.Data}'))
                socket.close()
                return
            if str(m_packet.Type) == '20':  # Parent advertise
                src_id = m_packet.SourceID
                child_id = m_packet.PrevID
                for ch in children.keys():
                    if ch.id == child_id:
                        children[ch].append(src_id)
                add_to_known_nodes(Child(0, src_id))
                if parent_id != '-1':
                    transfer_data(
                        Packet(20, src_id, parent_id, m_packet.PrevID, m_packet.Data))
                socket.close()
                return
            if str(m_packet.Type) == '21':  # Advertise
                src_id = m_packet.SourceID
                dest_id = m_packet.DestinationID
                prev_id = m_packet.PrevID
                if dest_id == user_id:  # Add to known_nodes
                    add_to_known_nodes(Child(0, src_id))
                elif dest_id == '-1':  # Add to known_nodes and forward
                    add_to_known_nodes(Child(0, src_id))
                    transfer_data(
                        Packet(21, src_id, dest_id, m_packet.PrevID, m_packet.Data))
                else:  # Forward packet
                    transfer_data(
                        Packet(21, src_id, dest_id, m_packet.PrevID, m_packet.Data))
                socket.close()
                return
            if str(m_packet.Type) == '31':  # Destination not found message
                dest_id = m_packet.DestinationID
                if dest_id == user_id:
                    print(m_packet.Data)
                else:
                    transfer_data(Packet(31, m_packet.SourceID,
                                         dest_id, m_packet.PrevID, m_packet.Data))
                socket.close()
                return
            if str(m_packet.Type) == '0':  # Message
                src_id = m_packet.SourceID
                dest_id = m_packet.DestinationID
                prev_id = m_packet.PrevID
                if m_packet.DestinationID == user_id or m_packet.DestinationID == '-1':
                    add_to_known_nodes(
                        Child(socket.getsockname()[1], m_packet.DestinationID))

                if m_packet.Data.__contains__("Salam Salam Sad Ta Salam"):
                    if dest_id == user_id or dest_id == -1:
                        transfer_data(Packet(
                            0, user_id, src_id, user_id, "Hezaro Sisad Ta Salam"))
                    elif dest_id != user_id or dest_id == -1:
                        transfer_data(
                            Packet(0, src_id, dest_id, prev_id, m_packet.Data))
                    # socket.close()
                    return
                elif m_packet.Data.__contains__("Hezaro Sisad Ta Salam"):
                    if dest_id == user_id:
                        print("Hezaro Sisad Ta Salam")
                    else:
                        transfer_data(
                            Packet(0, src_id, dest_id, prev_id, m_packet.Data))
                    # socket.close()
                    return

                if m_packet.DestinationID == user_id:
                    if (not in_chat) and m_packet.Data.__contains__("REQUESTS FOR STARTING CHAT WITH "):
                        data = m_packet.Data.split('\n')[1]
                        chat_name = data.split(' ')[5]
                        ids_str = data.split(':')[1].split(',')
                        wait_for_answer = 1
                        print(str(chat_name) + " with id " + ids_str[
                            0].strip() + " has asked you to join a chat. Would you like to join?[Y/N]")
                        while wait_for_answer <= 1:
                            pass
                        answ = command
                        if answ == "Y":
                            ids = []
                            print("Choose a name for yourself")
                            while wait_for_answer <= 2:
                                pass
                            name = command
                            for element in ids_str:
                                ids.append(element.strip())
                                if element.strip() != user_id:
                                    add_to_known_nodes(Child(0, element.strip))
                                    transfer_data(
                                        Packet(0, m_packet.SourceID, element.strip(), m_packet.PrevID,
                                               "CHAT:\n" + user_id + " :" + str(name)))
                            my_chat = Chat(name, user_id, ids)
                            for element in chat_names:
                                my_chat.change(element[0], element[1])
                            chat_names = []
                            in_chat = True
                        wait_for_answer = 0
                        return
                    elif len(m_packet.Data.split(' ')) == 2 and m_packet.Data.__contains__(":") \
                            and m_packet.Data.__contains__("CHAT:\n"):
                        data = m_packet.Data.split('\n')[1]
                        id = data.split(' ')[0]
                        chat_name = data.split(':')[1]
                        if in_chat:
                            my_chat.change(id, chat_name)
                            print(f"{chat_name}({id}) was joined to the chat")
                        else:
                            chat_names.append((id, chat_name))
                        return
                    elif m_packet.Data.__contains__("EXIT CHAT") and in_chat:
                        id = m_packet.Data.split('\n')[1].split(' ')[2]
                        my_chat.left(id)
                        print(f"{my_chat.find_name(id)}({id}) left the chat.")
                        return
                    elif in_chat:
                        print(m_packet.Data.split('\n')[1])
                        return
                else:
                    print(m_packet.DestinationID)
                    transfer_data(m_packet)
                    return
        except:
            traceback.print_exc()
            print("client disconnected")
            socket.close()
            break


def server_side():
    global user_id, accepted
    while my_server_port == 0:
        time.sleep(1)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, my_server_port))
    server.listen()
    while True:
        try:
            client_socket, address = server.accept()
            thread = threading.Thread(target=handle, args=(client_socket,))
            thread.start()
        except:
            traceback.print_exc()
            client.close()
            break


def client_side():
    global user_id, my_server_port, my_chat, in_chat, accepted, \
        client, parent_id, parent_port, my_server_port, host, admin_port, \
        known_nodes, chat_names, fw_table, fw_blocked_chat, wait_for_answer, command
    while True:
        try:
            command = input(">> ")
            if wait_for_answer > 0:
                print(command)
                wait_for_answer += 1
                continue
            elif (not accepted) and re.match(r'^CONNECT AS (.+) ON PORT (.+)$', command) is not None:
                match_obj = re.match(
                    r'^CONNECT AS (.+) ON PORT (.+)$', command)
                user_id = match_obj.group(1)
                my_server_port = int(match_obj.group(2))
                fw_table = FwTable(user_id)
                m_packet = Packet(0, user_id, admin_port, user_id,
                                  f'{user_id} REQUESTS FOR CONNECTING TO NETWORK ON PORT {my_server_port}')
                client.send(pickle.dumps(m_packet))

                # wait for admin, assumption: always send something as response: fail or ok
                answer = client.recv(4096)
                m_packet = pickle.loads(answer)
                if re.match(r'^CONNECT TO (.+) WITH PORT (.+)$', m_packet.Data) is not None:
                    match_obj = re.match(
                        r'^CONNECT TO (.+) WITH PORT (.+)$', m_packet.Data)
                    parent_id = match_obj.group(1)
                    parent_port = int(match_obj.group(2))
                    accepted = True
                    client.close()
                    if parent_id != '-1':
                        # add parent to known nodes
                        add_to_known_nodes(Child(parent_port, parent_id))
                        transfer_data(
                            Packet(41, user_id, parent_id, user_id, str(my_server_port)))
                else:
                    print("You are not accepted by admin, retry!!!")
            elif accepted:
                if in_chat:
                    if command.__contains__("EXIT CHAT"):
                        in_chat = False
                        for element in my_chat.others:
                            if str(element[0]) != str(user_id):
                                # print(element)
                                # print("اااااااااااااااااا")
                                transfer_data(Packet(0, user_id, element[0], user_id,
                                                     "CHAT:\nEXIT CHAT " + str(user_id)))
                        my_chat = None
                    else:
                        for element in my_chat.others:
                            if element[0] != user_id:
                                transfer_data(Packet(0, user_id, element[0], user_id,
                                                     "CHAT\n" + str(my_chat.my_name) + ": "+ str(command)))
                elif re.match(r'^Salam Salam Sad Ta Salam (.+)$', command) is not None:
                    dest_id = command.split(' ')[5]
                    transfer_data(Packet(0, user_id, dest_id, user_id,
                                         "Salam Salam Sad Ta Salam"))
                elif re.match(r'^SHOW KNOWN CLIENTS$', command) is not None:
                    for node in known_nodes:
                        print(node.id)
                # START CHAT CHAT_NAME: ID, ID, ...
                elif (not in_chat) and command.__contains__("START CHAT"):
                    if fw_blocked_chat:
                        print(
                            '‫‪Chat‬‬ ‫‪is‬‬ ‫‪disabled.‬‬ ‫‪Make‬‬ ‫‪sure‬‬ ‫‪the‬‬ ‫‪firewall‬‬ ‫‪allows‬‬ ‫‪you‬‬ ‫‪to‬‬ ‫‪chat.‬‬')
                        continue
                    chat_name = command.split(' ')[2][:-1]
                    ids_str = command.split(':')[1].split(',')
                    ids = []
                    ids.append(user_id)
                    for element in ids_str:
                        if is_it_known(element.strip()):
                            ids.append(element.strip())
                            transfer_data(Packet(0, user_id, element.strip(), user_id,
                                                 "CHAT:\nREQUESTS FOR STARTING CHAT WITH " + chat_name +
                                                 ": " + str(user_id) + "," + command.split(':')[1]))
                    chat_names = []
                    my_chat = Chat(chat_name, user_id, ids)
                    in_chat = True
                elif re.match(r'^ROUTE (.+)$', command) is not None:
                    match_obj = re.match(r'^ROUTE (.+)$', command)
                    dest_id = match_obj.group(1)
                    if not is_it_known(dest_id):
                        print(f'Unknown destination {dest_id}')
                    else:
                        transfer_data(
                            Packet(10, user_id, dest_id, user_id, 'Empty-body'))
                elif re.match(r'^ADVERTISE (.+)$', command) is not None:
                    match_obj = re.match(r'^ADVERTISE (.+)$', command)
                    dest_id = match_obj.group(1)
                    transfer_data(
                        Packet(21, user_id, dest_id, user_id, 'Empty-body'))
                # todo: below case correct?
                elif re.match(r'^FW CHAT (ACCEPT|DROP)$', command) is not None:
                    match_obj = re.match(r'^FW CHAT (ACCEPT|DROP)$', command)
                    action = match_obj.group(1)
                    if action == 'DROP':
                        fw_blocked_chat = True
                    elif action == 'ACCEPT':
                        fw_blocked_chat = False
                    else:
                        assert 1 == 2
                elif re.match(r'^FILTER (INPUT|OUTPUT|FORWARD) (.+) (.+) (.+) (ACCEPT|DROP)$', command) is not None:
                    match_obj = re.match(
                        r'^FILTER (INPUT|OUTPUT|FORWARD) (.+) (.+) (.+) (ACCEPT|DROP)$', command)
                    fw_table.add_rule(match_obj.group(1), match_obj.group(2), match_obj.group(3),
                                      match_obj.group(4), match_obj.group(5))
                elif re.match(r'^FW REMOVE$', command) is not None:
                    fw_table.remove_rule(0)
                elif re.match(r'^FW PRINT$', command) is not None:
                    fw_table.print()
                else:
                    print('Wrong command.')
            else:
                print("You are not accepted by admin, retry!!!")
        except:
            traceback.print_exc()
            try:
                client.close()
            except:
                break
            break


server_thread = threading.Thread(target=server_side)
server_thread.start()

client_thread = threading.Thread(target=client_side)
client_thread.start()
