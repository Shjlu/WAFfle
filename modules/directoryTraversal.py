from .i_attack_checker import IAttackChecker
from .http_request import HttpRequest, MultipartFormData, DirectoryTraversal
import re


class DirectoryTraversalChecker(IAttackChecker):
    pattern = re.compile(
        r"\.\.(\\|\/|%5c|%2f)",
        re.IGNORECASE)

    def __init__(self, db):
        super().__init__(db, "DT")

    @IAttackChecker.checkWhitelist
    def isMalicious(self, req: HttpRequest):
        for value in req.get_params.content_dict.values():
            if re.search(self.pattern, value):
                raise DirectoryTraversal
                return

        post_params = req.post_params.content_dict
        for value in post_params.values():
            if type(value) == str:  # no sql injection in bytes like objects hopefully
                if re.search(self.pattern, value):
                    raise DirectoryTraversal
                    return
        return False
