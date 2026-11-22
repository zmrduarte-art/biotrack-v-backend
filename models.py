from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.sql import func
from database import Base

class Rol(Base):
    __tablename__ = "roles"
    id_rol = Column(Integer, primary_key=True, index=True)
    nombre_rol = Column(String(50), unique=True, nullable=False)
    descripcion = Column(Text, nullable=False)

class Usuario(Base):
    __tablename__ = "usuarios"
    id_usuario = Column(Integer, primary_key=True, index=True)
    nombre_completo = Column(String(120), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    id_rol = Column(Integer, ForeignKey("roles.id_rol"), nullable=False)
    activo = Column(Boolean, default=True, nullable=False)
    creado_en = Column(DateTime(timezone=True), server_default=func.now())

class EquipoRefrigeracion(Base):
    __tablename__ = "equipos_refrigeracion"
    id_equipo = Column(Integer, primary_key=True, index=True)
    codigo_equipo = Column(String(30), unique=True, nullable=False)
    nombre_equipo = Column(String(100), nullable=False)
    ubicacion = Column(String(100), nullable=False)
    temp_min = Column(Numeric(4, 1), default=2.0, nullable=False)
    temp_max = Column(Numeric(4, 1), default=8.0, nullable=False)
    estado_operativo = Column(String(20), default="NORMAL", nullable=False)

class Insumo(Base):
    __tablename__ = "insumos"
    id_insumo = Column(Integer, primary_key=True, index=True)
    codigo_insumo = Column(String(30), unique=True, nullable=False)
    nombre_insumo = Column(String(150), nullable=False)
    categoria = Column(String(50), nullable=False)
    requiere_cadena_frio = Column(Boolean, default=True, nullable=False)
    stock_minimo = Column(Integer, default=10, nullable=False)

class Lote(Base):
    __tablename__ = "lotes"
    id_lote = Column(Integer, primary_key=True, index=True)
    id_insumo = Column(Integer, ForeignKey("insumos.id_insumo"), nullable=False)
    id_equipo = Column(Integer, ForeignKey("equipos_refrigeracion.id_equipo"), nullable=True)
    codigo_lote = Column(String(50), nullable=False)
    fecha_vencimiento = Column(Date, nullable=False)
    cantidad_inicial = Column(Integer, nullable=False)
    cantidad_actual = Column(Integer, nullable=False)
    estado = Column(String(20), default="DISPONIBLE", nullable=False)
    creado_en = Column(DateTime(timezone=True), server_default=func.now())

class MovimientoInventario(Base):
    __tablename__ = "movimientos_inventario"
    id_movimiento = Column(Integer, primary_key=True, index=True)
    id_lote = Column(Integer, ForeignKey("lotes.id_lote"), nullable=False)
    id_usuario = Column(Integer, ForeignKey("usuarios.id_usuario"), nullable=False)
    tipo_movimiento = Column(String(30), nullable=False)
    cantidad = Column(Integer, nullable=False)
    observacion = Column(Text, nullable=True)
    fecha_movimiento = Column(DateTime(timezone=True), server_default=func.now())

class RegistroTemperatura(Base):
    __tablename__ = "registros_temperatura"
    id_registro = Column(Integer, primary_key=True, index=True)
    id_equipo = Column(Integer, ForeignKey("equipos_refrigeracion.id_equipo"), nullable=False)
    id_usuario = Column(Integer, ForeignKey("usuarios.id_usuario"), nullable=False)
    temperatura_c = Column(Numeric(4, 1), nullable=False)
    es_excursion = Column(Boolean, nullable=False)
    observacion = Column(Text, nullable=True)
    fecha_registro = Column(DateTime(timezone=True), server_default=func.now())

class AuditoriaLog(Base):
    __tablename__ = "auditoria_logs"
    id_log = Column(Integer, primary_key=True, index=True)
    id_usuario = Column(Integer, ForeignKey("usuarios.id_usuario"), nullable=True)
    accion = Column(String(100), nullable=False)
    entidad_afectada = Column(String(50), nullable=False)
    id_registro_afectado = Column(Integer, nullable=True)
    detalle = Column(Text, nullable=False)
    ip_origen = Column(String(45), nullable=True)
    fecha_evento = Column(DateTime(timezone=True), server_default=func.now())