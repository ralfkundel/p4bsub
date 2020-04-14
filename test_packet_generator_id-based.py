#!/usr/bin/python

from scapy.all import *
from scapy.layers.l2 import Ether


class EventHeader(Packet):
    name = "EventHeader "
    fields_desc = [
        ByteField("mask", 0)
    ]


class Event(Packet):
    name = "EventValue "
    fields_desc = [
        IntField("value", 0)
    ]

class EventBuilder:
    mask = set()
    values = {}

    __maxValues = 8

    def add(self, aid, value):
        if aid < self.__maxValues and aid >= 0:
            self.mask.add(aid)
            self.values[aid] = value

    def build(self):
        def mask_to_int():
            s = ""
            for i in range(self.__maxValues):
                if i in self.mask:
                    s += "1"
                else:
                    s += "0"

            print("Bitmask: " + s + " " + str(hex(int(s, 2))))
            print()
            return int(s, 2)

        included = list(self.values.keys())
        included.sort()

        if len(included) == 0:
            raise Exception("You need to specify at least one value.")

        ret = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x9001) / EventHeader(mask=mask_to_int())

        for index, aid in enumerate(included):
            # if index+1 >= len(included):
            #     next = 0
            # else:
            #     next = included[index+1]

            ret = ret / Event(value=self.values[aid])

        return ret


event = EventBuilder()
event.add(0, 230)
event.add(1, 230)
event.add(3, 30)


print("Sending...")
#hexdump()
sendp(event.build())
