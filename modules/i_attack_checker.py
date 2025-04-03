from .http_request import HttpRequest
from abc import ABC, abstractmethod
import functools


class IAttackChecker(ABC):
    def __init__(self, db, attack_flag):
        self.db = db
        self.attack_flag = attack_flag


    def checkWhitelist(func):
        @functools.wraps(func)
        def wrap(self: IAttackChecker , req):
            ignored_attacks = self.db.get_whitelist(req.headers['Host'].split(':')[0], req.endpoint)
            return func(self, req) if self.attack_flag not in ignored_attacks else False

        return wrap

    @abstractmethod
    def isMalicious(self, req: HttpRequest) -> bool:
        pass
