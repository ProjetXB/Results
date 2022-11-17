# -*- coding: utf-8 -*-
import sqlalchemy
from sqlalchemy import Column
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

engine = create_engine('sqlite:///xbt.sqlite', echo=False)
Base = declarative_base(bind=engine)


class Packet(Base):
    __tablename__ = 'PACKET'
    id = Column("ID", sqlalchemy.Integer, primary_key=True)
    pcap_file = Column("PCAP_FILE", sqlalchemy.String, nullable=False, unique=False)
    patient_id = Column("PATIENT_ID", sqlalchemy.String, nullable=False, unique=False)
    source = Column("SOURCE", sqlalchemy.String, nullable=False, unique=False)
    raw = Column("RAW", sqlalchemy.String, nullable=False, unique=False)
    timestamp = Column("TIMESTAMP", sqlalchemy.Float, nullable=False, unique=False)
    action = Column("ACTION", sqlalchemy.String, nullable=False, unique=False)
    layers = Column("LAYERS", sqlalchemy.String, nullable=False, unique=False)
    

    valid = Column("VALID", sqlalchemy.Boolean, nullable=True, unique=False)
    pdu_type = Column("PDU_TYPE", sqlalchemy.Integer, nullable=True, unique=False)
    mac = Column("MAC", sqlalchemy.String, nullable=True, unique=False)
    crc = Column("CRC", sqlalchemy.Boolean, nullable=True, unique=False)

    profile = Column("PROFILE", sqlalchemy.String, nullable=True, unique=False)
    comment = Column("COMMENT", sqlalchemy.String, nullable=True, unique=False)

    eir_trace = Column("EIR_TRACE", sqlalchemy.String, nullable=True, unique=False)
    unique_mac = Column("UNIQUE_MAC", sqlalchemy.Boolean, nullable=True, unique=False)

class Patient(Base):
    __tablename__ = 'PATIENT'
    id = Column("ID", sqlalchemy.Integer, primary_key=True)
    patient_id = Column("PATIENT_ID", sqlalchemy.String, nullable=False, unique=True)
    

    begin = Column("BEGIN", sqlalchemy.Float, nullable=False, unique=False)
    end = Column("END", sqlalchemy.Float, nullable=False, unique=False)
    pdu0 = Column("PDU0", sqlalchemy.Integer, nullable=False, unique=False)
    pdu1_6 = Column("PDU1_6", sqlalchemy.Integer, nullable=False, unique=False)
    pdu_unknown = Column("PDU_UNKNOWN", sqlalchemy.Integer, nullable=False, unique=False)

    mac_total = Column("MAC_TOTAL", sqlalchemy.Integer, nullable=False, unique=False)
    mac_usable = Column("MAC_USABLE", sqlalchemy.Integer, nullable=False, unique=False)



def get_or_create(session_, model, defaults=None, **kwargs):
    instance = session_.query(model).filter_by(**kwargs).first()
    if instance:
        return instance, False
    else:
        params = dict((k, v) for k, v in kwargs.iteritems())
        params.update(defaults or {})
        instance = model(**params)
        session_.add(instance)
        session_.commit()
        return instance, True


Base.metadata.create_all()
Session = sessionmaker(bind=engine)

session = Session()


def add(element):
    try:
        session.add(element)
    except sqlalchemy.exc.IntegrityError as e:
        session.rollback()
        return False
    return True


def add_Commit(element):
    try:
        session.add(element)
        session.commit()
    except sqlalchemy.exc.IntegrityError as e:
        return False
    return True


def commit():
    try:
        session.commit()
    except sqlalchemy.exc.IntegrityError as e:
        return False
    return True
