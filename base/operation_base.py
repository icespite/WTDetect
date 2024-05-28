from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import List


class Point:
    def __init__(self, clazz, text, bounds):
        self.clazz = clazz
        self.coord = (
            (bounds[2] - bounds[0]) / 2 + bounds[0],
            (bounds[3] - bounds[1]) / 2 + bounds[1],
        )
        self.text = text
        self.width = bounds[2] - bounds[0]
        self.height = bounds[3] - bounds[1]
        self.size = (self.width, self.height)
        self.bounds = bounds

    def __str__(self):
        return f"Clazz: {self.clazz}, Coord: {self.coord}, Text: {self.text}, Size: {self.size}, Bounds: {self.bounds}"

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, Point):
            return self.coord == __value.coord
        return False


class SingleOperation(Enum):
    CLICK = "click"
    SWIPE_DOWN = "swipe_down"
    SWIPE_UP = "swipe_up"
    ROLLBACK = "rollback"


class Operation:
    def __init__(self, operation_type: SingleOperation, point: Point):
        if not isinstance(operation_type, SingleOperation):
            raise ValueError("operation_type must be a member of SingleOperation enum")
        self.operation_type = operation_type
        self.point = point
        self.num = 0
        self.weight = 0

    def __str__(self):
        return f"Operation: {self.operation_type}, Weight: {self.weight}, Point: {self.point}"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, Operation):
            return (
                self.operation_type == __value.operation_type
                and self.point == __value.point
            )
        return False

    def __hash__(self) -> int:
        return hash((self.operation_type, self.point.coord))


class ParseTool(metaclass=ABCMeta):
    @abstractmethod
    def getQueueOperation(self, node) -> List[Operation]:
        pass

    def getTreeOperation(self, root) -> List[Operation]:
        pass


class ParseFactory(metaclass=ABCMeta):
    @abstractmethod
    def getOperations(self, source) -> List[Operation]:
        pass
