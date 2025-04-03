from .i_attack_checker import IAttackChecker
from .http_request import HttpRequest, MultipartFormData
import re


class XXEChecker(IAttackChecker):
    pattern = re.compile(r'<!ENTITY\s+\S+\s+SYSTEM\s+[\'\"].+[\'\"]>')

    def __init__(self, db):
        super().__init__(db, "XXE")

    @IAttackChecker.checkWhitelist
    def isMalicious(self, req: HttpRequest):
        if "Content-Type" in req.headers and (req.headers["Content-Type"] == "text/xml" or req.headers["Content-Type"] == "application/xml"):
            if re.search(self.pattern, req.body.decode()):
                raise XXEChecker
                return
