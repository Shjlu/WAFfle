from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, relationship
from sqlalchemy import String, Integer, Text, ForeignKey, Boolean, DateTime
from typing import List
from flask_sqlalchemy import SQLAlchemy
from bcrypt import hashpw
import datetime


class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    salt: Mapped[str] = mapped_column(String, unique=True, nullable=False)

    def verify_password(self, password: str) -> bool:
        return hashpw(password.encode('utf-8'), self.salt.encode('utf-8')).decode() == self.password

class BlackListEntry(Base):
    __tablename__ = 'blacklist'
    ip: Mapped[str] = mapped_column(Text, primary_key=True)
    date: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)

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

    website: Mapped["WebsiteConfig"] = relationship(back_populates="blocked_country_codes")
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
    date: Mapped[str] = mapped_column()
    urgency: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # 1 - delete itself every day
    relevant_ip: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(String)

class WebsiteWhitelistedEndpoints(Base):
    __tablename__ = 'website_whitelist'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    endpoint: Mapped[str] = mapped_column(String, nullable=False)
    SQLi: Mapped[bool] = mapped_column(Boolean, default=False)
    XXE: Mapped[bool] = mapped_column(Boolean, default=False) 
    DT: Mapped[bool] = mapped_column(Boolean, default=False) 

    website_id: Mapped[str] = mapped_column(ForeignKey('websites.id'))

db = SQLAlchemy(model_class=Base)
