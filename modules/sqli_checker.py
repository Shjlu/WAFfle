from .i_attack_checker import IAttackChecker
from .http_request import HttpRequest, MultipartFormData, SQLInjection
import re


class SQLiChecker(IAttackChecker):
    pattern = re.compile(
        r"\s*[\'\"\;]*\s*(((UNION)*SELECT\s+\S+\sFROM\s+\S+)|(DROP\s+\S+)|(ALTER\s+\S+)|(INSERT\s+INTO\s+\S+\s+VALUES\s+\S+)|(DELETE\s+FROM\s+\S+)|(UPDATE\s+\w+\s+SET\s+(\S+\s*\=\s*\S+\s*\,*)+)|((ALL|NOT|LIKE|AND|OR)\s+\S+\s*[\<\>\=\!\~]+\s*\S+)|(LET\s+\S+\s+AS\s+\S+))\s*;*\s*(--|#)*",
        re.IGNORECASE)

    def __init__(self, db):
        super().__init__(db, "SQLi")

    @IAttackChecker.checkWhitelist
    def isMalicious(self, req: HttpRequest):
        for value in req.get_params.content_dict.values():
            if re.search(self.pattern, value):
                raise SQLInjection
               

        post_params = req.post_params.content_dict
        for value in post_params.values():
            if type(value) == str:  # no sql injection in bytes like objects hopefully
                if re.search(self.pattern, value):
                    raise SQLInjection
                    
