import datetime
import time


class WatchDog:
    def __init__(self, name, runtime):
        """
        Initializes a Watchdog object.

        Args:
            name (str): The name of the watchdog.
            runtime (float): The runtime of the watchdog in seconds.
        """
        self.name = name
        time_now = time.time()
        self.last_time = time_now
        self.begin_time = time_now
        self.end_time = time_now
        self.runtime = runtime

    def is_alive(self):
        if time.time() - self.begin_time > self.runtime:
            return False
        if time.time() - self.last_time > 30:
            if time.time() - self.end_time > 30:
                return False
        return True

    def update_last_time(self):
        self.last_time = time.time()

    def update_end_time(self):
        self.end_time = time.time()

    def show(self):
        begin_time_formatted = datetime.datetime.fromtimestamp(
            self.begin_time
        ).strftime("%Y-%m-%d %H:%M:%S")
        last_time_formatted = datetime.datetime.fromtimestamp(self.last_time).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        end_time_formatted = datetime.datetime.fromtimestamp(self.end_time).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        print(
            f"{self.name} Start Time: {begin_time_formatted}, "
            f"Last Start Time: {last_time_formatted}, "
            f"Last End Time: {end_time_formatted}, "
            f"Total Run Time Difference (s): {self.end_time - self.begin_time}"
        )
