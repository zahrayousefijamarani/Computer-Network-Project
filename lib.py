import enum
from sys import path_importer_cache
from typing import Pattern


class Client:
    def __init__(self, socket, address, port, id):
        self.socket = socket
        self.address = address
        self.port = port
        self.id = id
        self.parent = None


class Child:
    def __init__(self, port: int, id: str):
        self.port = port
        self.id = id


class Chat:
    def __init__(self, my_name, my_user_id, others):
        self.my_name = my_name
        self.others = []
        for element in others:
            if isinstance(element, str):
                if element == my_user_id:
                    self.others.append((my_user_id, my_name))
                else:
                    self.others.append((element, ""))
            else:
                self.others.append(element)

    def change(self, user_id, my_name):
        a = []
        for element in self.others:
            if element[0] == user_id:
                a.append((user_id, my_name))
            else:
                a.append(element)
        self.others.clear()
        self.others = a

    def find_name(self, id):
        for element in self.others:
            if element[0] == id:
                return element[1]
        return ""

    def left(self, id):
        a = []
        for element in self.others:
            if element[0] == id:
                continue
            else:
                a.append(element)
        self.others.clear()
        self.others = a


class Packet:
    def __init__(self, Type, SourceID, DestinationID, PrevID, Data):
        self.Type = Type
        self.SourceID = SourceID
        self.DestinationID = DestinationID
        self.PrevID = PrevID
        self.Data = Data

    def print_summary(self):
        print(f'{self.Type} Packet from {self.SourceID} to {self.DestinationID}')

    def print_complete(self):
        print('-------------------------------')
        print(f'Type: {self.Type}')
        print(f'Source ID: {self.SourceID}')
        print(f'Destination ID: {self.DestinationID}')
        print(f'Previous ID: {self.PrevId}')
        print('Data:')
        print(self.Data)
        print('-------------------------------')


# Firewall Table
class FwTable:
    def __init__(self, owner_id):
        self.owner_id = owner_id
        self.fw_rules = []

    # Add new rule to fire wall table
    def add_rule(self, dir: str, id_src, id_dest, type_, action):
        new_rule = {'dir': dir, 'id_src': '-1' if id_src == '*' else id_src,
                    'id_dest': '-1' if id_dest == '*' else id_dest, 'type': type_, 'action': action}
        self.fw_rules.insert(0, new_rule)

    def remove_rule(self, index: int):
        if 0 <= index < len(self.fw_rules):
            self.fw_rules.pop(index)
        else:
            print('Out of range index for deleting rule from firewall table.')

    # Shows whether a packet is allowed to pass firewall or must be dropped.
    # The packet Will be accepted if it matches no rule.
    def does_packet_pass_fw(self, packet: Packet):
        for rule in self.fw_rules:
            if self.does_packet_match_rule(packet, rule):
                print(rule)
                return rule['action'] == 'ACCEPT'
        return True

    def does_packet_match_rule(self, packet: Packet, rule: dict):
        if rule['dir'] == 'INPUT':
            if (rule['id_src'] == packet.SourceID or rule['id_src'] == '-1') and \
                packet.DestinationID == self.owner_id and \
                    rule['type'] == str(packet.Type):
                return True
            else:
                return False
        elif rule['dir'] == 'OUTPUT':
            if packet.SourceID == self.owner_id and \
                (rule['id_dest'] == packet.DestinationID or rule['id_dest'] == '-1') and \
                    rule['type'] == str(packet.Type):
                return True
            else:
                return False
        elif rule['dir'] == 'FORWARD':
            if (rule['id_src'] == packet.SourceID or rule['id_src'] == '-1') and \
                packet.SourceID != self.owner_id and \
                (rule['id_dest'] == packet.DestinationID or rule['id_dest'] == '-1') and \
                packet.DestinationID != self.owner_id and \
                    rule['type'] == str(packet.Type):
                return True
            else:
                return False
        else:
            assert 1 == 2  # report bug

    def print(self):
        print('Firewall rules:')
        for i, rule in enumerate(self.fw_rules):
            print(f'{i}. Direction: {rule["dir"]}, SrcID: {rule["id_src"]}, \
                DestID: {rule["id_dest"]}, Type: {rule["type"]}, Action: {rule["action"]}')


class PacketType(enum.Enum):
    Message = 0
    RoutingRequest = 10
    RoutingResponse = 11
    ParentAdvertise = 20
    Advertise = 21
    DestinationNotFoundMessage = 31
    ConnectionRequest = 41


class Tree:
    def __init__(self):
        self.left = None
        self.right = None
        self.Node = None
        self.left_count = 0
        self.right_count = 0

    def insert(self, c):
        if self.Node is None:
            if self.left_count == 0 and self.right_count == 0:  # is the root
                self.Node = c
                return Client(None, None, -1, -1)
            # not happening
            # else:
            #     self.tree.Node = c
            #     self.counter += 1
            #     return self.tree
        elif self.left is None:
            a = Tree()
            a.Node = c
            self.left = a
            self.left_count += 1
            return self.Node
        elif self.right is None:
            a = Tree()
            a.Node = c
            self.right = a
            self.right_count += 1
            return self.Node
        elif self.left_count <= self.right_count:
            self.left_count += 1
            return self.left.insert(c)
        else:
            self.right_count += 1
            return self.right.insert(c)
