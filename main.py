import threading

import proxy
from modules.config import Config
import logging_server
from modules.db import DB
import dashboard 

if __name__ == "__main__":
    config = Config("./config.json")
    db = DB(config.pstg_user,
            config.pstg_password,
            config.pstg_db,
            config.pstg_host,
            config.pstg_port)
    
    proxy_thread = threading.Thread(target=proxy.Proxy(db, config).listen)
    log_thread = threading.Thread(target=logging_server.start_logging)

    proxy_thread.start()
    log_thread.start()
