import json


class Config:
    def __init__(self, filename: str):
        with open("./config.json", "r") as f:
            self.raw = json.load(f)

        try:
            self.proxy_ip = self.raw["proxy_ip"]
            self.proxy_port = self.raw["proxy_port"]
            self.target_ip = self.raw["target_ip"]
            self.target_port = self.raw["target_port"]

            self.whitelist = self.raw["whitelist"]

            self.pstg_host = self.raw["postgresql_ip"]
            self.pstg_port = self.raw["postgresql_port"]
            self.pstg_db = self.raw["postgresql_db"]
            self.pstg_user = self.raw["postgresql_user"]
            self.pstg_password = self.raw["postgresql_password"]

            self.db_conn_pool_min = self.raw["db_conn_pool_min"]
            self.db_conn_pool_max = self.raw["db_conn_pool_max"]



        except:
            raise ValueError("Invalid config.")
