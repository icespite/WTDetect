import math
import re
import xml.etree.ElementTree as ET
from typing import List

from base.operation_base import (
    Operation,
    ParseFactory,
    ParseTool,
    Point,
    SingleOperation,
)


class ParseFactoryElementTree(ParseFactory):
    def __init__(self, parse_tools: List[ParseTool]):
        self.parse_tools = parse_tools
        print(
            "included operations: ",
            [tool.__class__.__name__ for tool in self.parse_tools],
        )
        self.sort = True

    def getOperations(self, source) -> List[Operation]:
        root = ET.fromstring(source)
        queue_operations = self.getQueueOperations(root)
        tree_operations = self.getTreeOperations(root)
        queue_operations.extend(tree_operations)

        if self.sort:
            return sorted(
                list(set(queue_operations)), key=lambda x: x.weight, reverse=True
            )
        else:
            return queue_operations

    def getQueueOperations(self, root) -> List[Operation]:
        operations = []
        stack = [root]
        while stack:
            node = stack.pop()
            for tool in self.parse_tools:
                operations.extend(tool.getQueueOperation(node))
            for child in reversed(list(node)):
                stack.append(child)
        return operations

    def getTreeOperations(self, root) -> List[Operation]:
        operations = []
        for tool in self.parse_tools:
            operations.extend(tool.getTreeOperation(root))
        return operations


class ParseClickElementTree(ParseTool):
    def __init__(self, weight=0) -> None:
        super().__init__()
        self.weight = weight

    def getQueueOperation(self, node):
        attrs = node.attrib
        if "clickable" in attrs and attrs["clickable"] == "true":
            reg = re.compile(r"\d+")
            data = [int(i) for i in re.findall(reg, attrs["bounds"])]
            bounds = data
            point = Point(attrs["class"], attrs["text"], bounds)
            op = Operation(SingleOperation.CLICK, point)
            op.weight = self.weight
            return [op]
        else:
            return []

    def getTreeOperation(self, root):
        return []


class ParseSwipeElementTree(ParseTool):
    def __init__(self, weight=0) -> None:
        super().__init__()
        self.weight = weight

    def getQueueOperation(self, node):
        attrs = node.attrib
        if "scrollable" in attrs and attrs["scrollable"] == "true":
            reg = re.compile("\d+")
            data = [int(i) for i in re.findall(reg, attrs["bounds"])]
            bounds = data
            point = Point(attrs["class"], attrs["text"], bounds)
            op = Operation(SingleOperation.SWIPE_UP, point)
            op.weight = self.weight
            return [op]
        else:
            return []

    def getTreeOperation(self, root):
        return []


class ParseImageElementTree(ParseTool):
    def __init__(self, weight=0) -> None:
        super().__init__()
        self.weight = weight

    def getQueueOperation(self, node):
        attrs = node.attrib
        if "class" in attrs and (
            "imageview" in attrs["class"].lower()
            or "webview" in attrs["class"].lower()
            or "viewflipper" in attrs["class"].lower()
        ):
            reg = re.compile("\d+")
            data = [int(i) for i in re.findall(reg, attrs["bounds"])]
            bounds = data
            point = Point(attrs["class"], attrs["text"], bounds)
            op = Operation(SingleOperation.CLICK, point)
            op.weight = self.weight
            return [op]
        else:
            return []

    def getTreeOperation(self, root):
        return []


class ParseAdElementTree(ParseTool):

    def getQueueOperation(self, node):
        return []

    def getTreeOperation(self, root):
        class AdLevel:
            def __init__(self, tree_level, operation, node):
                self.tree_level = tree_level
                self.operation = operation
                self.node = node

        ad_weight = 30
        ad_levels = []
        ad_gap = 3
        operations_adlevel = []
        stack = [AdLevel(0, None, root)]
        while stack:
            cur_ad_level = stack.pop()
            attrs = cur_ad_level.node.attrib
            if "class" in attrs and (
                "imageview" in attrs["class"].lower()
                or "webview" in attrs["class"].lower()
                or "viewflipper" in attrs["class"].lower()
                # or "textview" in attrs["class"].lower()
            ):
                reg = re.compile("\d+")
                data = [int(i) for i in re.findall(reg, attrs["bounds"])]
                bounds = data
                point = Point(attrs["class"], attrs["text"], bounds)
                operation = Operation(SingleOperation.CLICK, point)
                operation.weight = self.logarithmic_mapping(
                    point.size[0] * point.size[1], 0, 1080 * 2400, 1, 80
                )
                if "clickable" in attrs and attrs["clickable"] == "true":
                    operation.weight += 10
                else:
                    operation.weight -= 20
                cur_ad_level.operation = operation
                # print("cur_ad_level:", cur_ad_level.tree_level, operation)
                operations_adlevel.append(cur_ad_level)
            if "text" in attrs and (
                "广告" in attrs["text"] or "ad" in attrs["text"].lower()
            ):
                ad_levels.append(cur_ad_level.tree_level)
            for child in reversed(list(cur_ad_level.node)):
                stack.append(AdLevel(cur_ad_level.tree_level + 1, None, child))
        operations = []
        for i in ad_levels[:]:
            for j in range(ad_gap):
                j = j + 1
                ad_levels.append(i + j)
                ad_levels.append(i - j)
        ad_levels = list(set(ad_levels))
        print("ad_levels:", ad_levels)
        for i in operations_adlevel:
            if i.tree_level in ad_levels:
                i.operation.weight += ad_weight
            else:
                if "textview" in i.node.attrib["class"].lower():
                    continue
            operations.append(i.operation)
        return operations

    def logarithmic_mapping(self, size, size_min, size_max, weight_min, weight_max):
        w_prime_min = math.log(1)
        w_prime_max = math.log(size_max + 1 - size_min)
        w_prime = math.log(size + 1 - size_min)
        weight = weight_min + (w_prime - w_prime_min) * (weight_max - weight_min) / (
            w_prime_max - w_prime_min
        )
        return weight


class ParseClickSwitchFirstElementTree(ParseTool):
    def __init__(self, heigth) -> None:
        super().__init__()
        self.height = heigth

    def getQueueOperation(self, node):
        attrs = node.attrib
        if "clickable" in attrs and attrs["clickable"] == "true":
            reg = re.compile("\d+")
            data = [int(i) for i in re.findall(reg, attrs["bounds"])]
            bounds = data
            point = Point(attrs["class"], attrs["text"], bounds)
            op = Operation(SingleOperation.CLICK, point)
            op.weight = self.calculate_weight(self.height, bounds, 1, 40)
            return [op]
        else:
            return []

    def getTreeOperation(self, root):
        return []

    def calculate_weight(
        self, screen_height, element_bounds, weight_min=1, weight_max=10
    ):
        _, bottom, _, top = element_bounds
        distance_to_top = screen_height - top
        distance_to_bottom = bottom
        min_distance = min(distance_to_top, distance_to_bottom)
        ratio = min_distance / screen_height
        weight = weight_max - ratio * (weight_max - weight_min)
        return weight
