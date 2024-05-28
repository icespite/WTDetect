import re
from typing import List
from xml.dom.minidom import parseString

from base.operation_base import (
    Operation,
    ParseFactory,
    ParseTool,
    Point,
    SingleOperation,
)


class ParseFactoryMinidom(ParseFactory):
    def __init__(self, parse_tools: List[ParseTool]):
        self.parse_tools = parse_tools
        print(
            "included operations: ",
            [tool.__class__.__name__ for tool in self.parse_tools],
        )

    def getQueueOperations(self, source) -> List[Operation]:
        operations = []
        root = parseString(source).documentElement
        queue = []
        queue.append(root)
        while queue:
            node = queue.pop(0)
            try:
                print(node.attributes.txt)
            except:
                pass
            for tool in self.parse_tools:
                operations.extend(tool.getQueueOperation(node))
            if len(node.childNodes) > 0:
                for child in node.childNodes:
                    if "#" not in child.nodeName:
                        queue.append(child)
        return list(set(operations))


class ParseClickMinidom(ParseTool):
    def getQueueOperation(self, node):
        attributes = node.attributes
        clickable = 0
        clazz = ""
        text = ""
        bounds = []
        for attr in attributes.items():
            if attr[0] == "class":
                clazz = attr[1]
            elif attr[0] == "text":
                text = attr[1]
            elif attr[0] == "clickable" and attr[1] == "true":
                clickable = 1
            elif attr[0] == "bounds":
                bounds_str = attr[1]
                reg = re.compile("\d+")
                data = [int(i) for i in re.findall(reg, bounds_str)]
                bounds = data
        if clickable == 1:
            return [
                Operation(
                    SingleOperation.CLICK,
                    Point(clazz, text, bounds),
                )
            ]
        else:
            return []

    def getTreeOperation(self, root):
        return []


class ParseSwipeMinidom(ParseTool):
    def getQueueOperation(self, node):
        attributes = node.attributes
        flag = 0
        clazz = ""
        text = ""
        bounds = []
        for attr in attributes.items():
            if attr[0] == "class":
                clazz = attr[1]
                if "recyclerview" in clazz.lower():
                    flag = 1
            elif attr[0] == "text":
                text = attr[1]
            elif attr[0] == "bounds":
                bounds_str = attr[1]
                reg = re.compile("\d+")
                data = [int(i) for i in re.findall(reg, bounds_str)]
                bounds = data

        if flag == 1:
            return [
                Operation(
                    SingleOperation.SWIPE_UP,
                    Point(clazz, text, bounds),
                )
            ]
        else:
            return []

    def getTreeOperation(self, root):
        return []
