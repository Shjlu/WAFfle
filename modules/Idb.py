from abc import ABC, abstractmethod


class Idb(ABC):
    @abstractmethod
    def add_to_blacklist(self, ip: str, date: str, reason: str):
        pass

    @abstractmethod
    def remove_from_blacklist(self, ip: str):
        pass

    @abstractmethod
    def register_user(self, username: str, password: str):
        pass

    @abstractmethod
    def remove_user(self, username: str, password: str):
        pass
