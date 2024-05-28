import hashlib
import random

from base.operation_base import ParseFactory, SingleOperation


class View:
    def __init__(self, source):
        self.name = ""
        self.cur = -1
        self.back_operation_pointer = None
        self.continue_visit = 0
        self.back = False
        self.activity_name = ""
        self.operations = []
        self.source = source

    def getNextOperation(self):
        if self.cur + 1 < len(self.operations) and self.cur + 1 >= 0:
            self.cur += 1
            return self.operations[self.cur]
        else:
            return None

    def getPerformanceStr(self):
        return (
            self.activity_name
            + " hash："
            + self.name
            + "  total number of operations："
            + str(len(self.operations))
            + "  Number of next click positions："
            + str(self.cur)
        )

    def parseSource(self, parse_factory: ParseFactory, shuffle=False):
        self.operations = parse_factory.getOperations(self.source)
        self.operations = self.remove_contained_operations(self.operations)
        hash_str = ""
        for opera in self.operations:
            hash_str += str(opera.operation_type) + str(opera.weight)
        hash_str = hash_str.encode("utf-8")
        hash_str = hashlib.md5(hash_str).hexdigest()
        self.name = hash_str
        if shuffle:
            random.shuffle(self.operations)

    def is_contained(self, child, parent):
        return all(child[i] >= parent[i] for i in range(2)) and all(
            child[i] <= parent[i] for i in range(2, 4)
        )

    def is_stay_operation(self, operation):
        keywords = [
            "后退",
            "返回",
            "关闭",
            "取消",
            "退出",
            "确定",
            "Back",
            "Return",
            "Close",
            "Cancel",
            "Exit",
            "Confirm",
        ]
        return any(keyword in operation.point.text for keyword in keywords)

    def remove_contained_operations(self, operations):
        removed_indices = set()
        for i, op1 in enumerate(operations):
            for j, op2 in enumerate(operations):
                if i != j and j not in removed_indices:
                    if op1.operation_type == op2.operation_type and self.is_contained(
                        op1.point.bounds, op2.point.bounds
                    ):
                        if not self.is_stay_operation(op2):
                            # print(f"remove {op2} because of {op1}")
                            removed_indices.add(j)
                    elif op1.operation_type == op2.operation_type and self.is_contained(
                        op2.point.bounds, op1.point.bounds
                    ):
                        if not self.is_stay_operation(op1):
                            # print(f"remove {op1} because of {op2}")
                            removed_indices.add(i)

        return [op for i, op in enumerate(operations) if i not in removed_indices]

    def remove_repeat_operations(self, operations):
        if not operations:
            return []
        filtered_operations = [operations[0]]
        for i in range(1, len(operations)):
            current_op = operations[i]
            previous_op = filtered_operations[-1]
            if not (
                current_op.operation_type == previous_op.operation_type
                and current_op.weight == previous_op.weight
            ) or self.is_stay_operation(current_op):
                filtered_operations.append(current_op)
        return filtered_operations

    def remove_repeat_operations_by_old_one(self, operations, old_operation):
        if not operations:
            return []
        filtered_operations = [operations[0]]
        for i in range(1, len(operations)):
            current_op = operations[i]
            if not (
                current_op.operation_type == old_operation.operation_type
                and current_op.weight == old_operation.weight
            ) or self.is_stay_operation(current_op):
                filtered_operations.append(current_op)
        return filtered_operations
