from .Idb import Idb
from contextlib import contextmanager
from sqlalchemy import create_engine, Integer, delete, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, scoped_session, relationship, mapped_column, Mapped, DeclarativeBase
from bcrypt import gensalt, hashpw
from typing import List
import random
import datetime


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    salt: Mapped[str] = mapped_column(String, unique=True, nullable=False)

    def __init__(self, username, password):
        """Sets the object using an unencrypted password, and encrypts it and adds salt with bcrypt

        :param username: str
        :type username: username
        :param password: str
        :type password: **UNENCRYPTED** password.
        """
        self.username = username
        self.salt = gensalt()
        self.password = hashpw(password, self.salt)


class BlackListEntry(Base):
    __tablename__ = 'blacklist'
    ip: Mapped[str] = mapped_column(String, primary_key=True)
    date: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(String)

    def __init__(self, ip, date, reason):
        self.ip = ip
        self.date = date
        self.reason = reason


class WebsiteConfig(Base):
    __tablename__ = 'websites'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    addresses: Mapped[List["WebsiteAddress"]] = relationship(back_populates="website")
    blocked_country_codes: Mapped[List["WebsiteBlockedCountry"]] = relationship()
    whitelisted_endpoints: Mapped[List["WebsiteWhitelistedEndpoints"]] = relationship()


class WebsiteBlockedCountry(Base):
    __tablename__ = 'blocked_countries'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    country: Mapped[str] = mapped_column(String)

    website_id: Mapped[str] = mapped_column(ForeignKey('websites.id'))


class WebsiteAddress(Base):
    __tablename__ = 'website_address'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)

    website: Mapped["WebsiteConfig"] = relationship(back_populates="addresses")
    website_id: Mapped[str] = mapped_column(ForeignKey('websites.id'))

class Logs(Base):
    __tablename__ = 'logs'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    log_type: Mapped[int] = mapped_column(Integer, nullable=False)
    date: Mapped[datetime.datetime] = mapped_column(String)
    urgency: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # 1 - delete itself every day
    relevant_ip: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(String)

    def __init__(self, log_type, date, urgency, relevant_ip, message):
        self.log_type = log_type
        self.date = date
        self.urgency = urgency
        self.relevant_ip = relevant_ip
        self.message = message

class WebsiteWhitelistedEndpoints(Base):
    __tablename__ = 'website_whitelist'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    endpoint: Mapped[str] = mapped_column(String, nullable=False)
    SQLi: Mapped[bool] = mapped_column(Boolean, default=False)
    XXE: Mapped[bool] = mapped_column(Boolean, default=False) 
    DT: Mapped[bool] = mapped_column(Boolean, default=False) 

    website_id: Mapped[str] = mapped_column(ForeignKey('websites.id'))

class DB(Idb):
    def __init__(self,
                 user: str,
                 password: str,
                 db: str,
                 host: str,
                 port: int):
        """Initiates the postgreSQL communicator

        :param user: user for the server
        :type user: str
        :param password: password for user
        :type password: str
        :param db: database name
        :type db: str
        :param host: address of the postgres server
        :type host: str
        :param port: port of the postgres server
        :type port: int
        """
        self.engine = create_engine(f"postgresql://{user}:{password}@{host}:{port}/{db}")
        self.Session = scoped_session(sessionmaker(bind=self.engine))

        self.initiate_db()

    def initiate_db(self):
        Base.metadata.create_all(bind=self.engine)

    @contextmanager
    def session_scope(self):
        session = self.Session()
        try:
            yield session
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def add_to_blacklist(self, ip: str, date: str, reason: str):
        with self.session_scope() as session:
            entry = BlackListEntry(ip, date, reason)
            session.add(entry)

    def add_to_logs(self, log_type: int, ip: str = None, date: datetime.datetime = datetime.datetime.now(), urgency: int = 1, message: str = ""):
        with self.session_scope() as session:
            entry = Logs(log_type=log_type, date=str(date), relevant_ip=ip, urgency=urgency, message=message)
            session.add(entry)

    def get_all_logs(self):
        with self.session_scope() as session:
            all_logs = session.query(Logs).all()
            session.expunge_all(all_logs)
        return all_logs

    def remove_from_blacklist(self, ip: str):
        with self.session_scope() as session:
            stmt = (delete(BlackListEntry).where(BlackListEntry.ip == ip))
            session.execute(stmt)

    def register_user(self, username: str, password: str):
        with self.session_scope() as session:
            entry = User(username, password)
            session.add(entry)

    def remove_user(self, username: str):
        with self.session_scope() as session:
            stmt = (delete(User).where(User.username == username))
            session.execute(stmt)

    def get_all_blocked_ip(self):
        with self.session_scope() as session:
            ips = [ip for ip, in
                   session.query(BlackListEntry.ip).all()]  # has to be unpacked as it returns list of one sized tuples
        return ips

    def get_blacklist_data(self):
        with self.session_scope() as session:
            blacklist_info = session.query(BlackListEntry).all()
        return blacklist_info

    def get_addresses_by_domain(self, domain: str):
        with self.session_scope() as session:
            addresses = session.query(WebsiteConfig).where(WebsiteConfig.domain == domain).first().addresses
            for i in addresses:
                session.expunge(i)
        return addresses

    def get_address_by_domain(self, domain: str):
        return random.choice(self.get_addresses_by_domain(domain))

    def get_blocked_countries(self, domain: str) -> List[str]:
        with self.session_scope() as session:
            blocked_countries: List[WebsiteBlockedCountry] = session.query(WebsiteConfig).where(WebsiteConfig.domain == domain).first().blocked_country_codes
            result = list(map(lambda x:  x.country, blocked_countries))
        return result
    
    def get_whitelist(self, domain: str, endpoint: str) -> List[str]:
        with self.session_scope() as session:
            whitelist = session.query(WebsiteConfig).where(WebsiteConfig.domain == domain).first().whitelisted_endpoints
            result = []
            for i in whitelist:
                if i.endpoint == endpoint:

                    if i.SQLi: result.append("SQLi")
                    if i.DT: result.append("DT")
                    if i.XXE: result.append("XXE")
        return result

