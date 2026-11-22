import os
from datetime import date
from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import SessionLocal, get_db
from models import (
    AuditoriaLog,
    EquipoRefrigeracion,
    Insumo,
    Lote,
    MovimientoInventario,
    RegistroTemperatura,
    Usuario,
)
from schemas import (
    DespachoFEFORequest,
    LiberarCuarentenaRequest,
    LoginRequest,
    LoteCreate,
    TemperaturaCreate,
)
from security import (
    create_access_token,
    get_current_user,
    hash_password,
    require_roles,
    verify_password,
)

app = FastAPI(
    title="BioTrack V API",
    description="API RESTful segura para gestión de insumos críticos y cadena de frío (CESFAM San Antonio)",
    version="1.0.0",
)

# Configuración CORS restringida (OWASP Top 10)
origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in origins],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Middleware de endurecimiento HTTP (Evidencia Sección 11 - OWASP ZAP)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path not in ["/docs", "/redoc", "/openapi.json"]:
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# Asegura que los usuarios iniciales de prueba tengan hash bcrypt válido para 'Admin123!'
@app.on_event("startup")
def init_seed_passwords():
    db = SessionLocal()
    try:
        for u in db.query(Usuario).all():
            if u.password_hash.endswith("HS.iK2."):
                u.password_hash = hash_password("Admin123!")
        db.commit()
    finally:
        db.close()

def registrar_auditoria(db: Session, id_usuario: int, accion: str, entidad: str, id_reg: Optional[int], detalle: str, request: Request):
    log = AuditoriaLog(
        id_usuario=id_usuario,
        accion=accion,
        entidad_afectada=entidad,
        id_registro_afectado=id_reg,
        detalle=detalle,
        ip_origen=request.client.host if request.client else "0.0.0.0",
    )
    db.add(log)

@app.get("/")
def health_check():
    return {"status": "online", "sistema": "BioTrack V API", "normativa": "ISO 27001 / OWASP"}

# RF01: Autenticación y emisión de JWT
@app.post("/api/auth/login")
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.email == data.email, Usuario.activo == True).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales incorrectas")

    token = create_access_token({"sub": str(user.id_usuario), "rol": user.id_rol})
    registrar_auditoria(db, user.id_usuario, "LOGIN_EXITOSO", "usuarios", user.id_usuario, f"Inicio de sesión de {user.email}", request)
    db.commit()

    return {
        "access_token": token,
        "token_type": "bearer",
        "usuario": {"id": user.id_usuario, "nombre": user.nombre_completo, "email": user.email, "id_rol": user.id_rol},
    }

# Consulta segura de insumos (Previene SQLi - Caso de Prueba CP-04)
@app.get("/api/insumos")
def listar_insumos(q: Optional[str] = None, current=Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(Insumo)
    if q:
        query = query.filter(Insumo.nombre_insumo.ilike(f"%{q}%"))
    return query.all()

@app.get("/api/equipos")
def listar_equipos(current=Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(EquipoRefrigeracion).all()

# RF02: Listar y crear lotes ordenados por vencimiento (FEFO)
@app.get("/api/lotes")
def listar_lotes(current=Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Lote).order_by(Lote.fecha_vencimiento.asc()).all()

@app.post("/api/lotes", status_code=201)
def crear_lote(
    data: LoteCreate,
    request: Request,
    current=Depends(require_roles(["ADMIN_QF", "OPERADOR_TENS"])),
    db: Session = Depends(get_db),
):
    nuevo_lote = Lote(
        id_insumo=data.id_insumo,
        id_equipo=data.id_equipo,
        codigo_lote=data.codigo_lote,
        fecha_vencimiento=data.fecha_vencimiento,
        cantidad_inicial=data.cantidad_inicial,
        cantidad_actual=data.cantidad_inicial,
        estado="DISPONIBLE",
    )
    db.add(nuevo_lote)
    db.flush()

    mov = MovimientoInventario(
        id_lote=nuevo_lote.id_lote,
        id_usuario=current["usuario"].id_usuario,
        tipo_movimiento="INGRESO",
        cantidad=data.cantidad_inicial,
        observacion="Ingreso inicial de lote",
    )
    db.add(mov)
    registrar_auditoria(db, current["usuario"].id_usuario, "INGRESO_LOTE", "lotes", nuevo_lote.id_lote, f"Ingreso lote {data.codigo_lote}", request)
    db.commit()
    db.refresh(nuevo_lote)
    return nuevo_lote

# RF03 y RF04: Registro de temperatura y bloqueo automático en CUARENTENA (Caso de Prueba CP-02)
@app.post("/api/temperaturas", status_code=201)
def registrar_temperatura(
    data: TemperaturaCreate,
    request: Request,
    current=Depends(require_roles(["ADMIN_QF", "OPERADOR_TENS"])),
    db: Session = Depends(get_db),
):
    equipo = db.query(EquipoRefrigeracion).filter(EquipoRefrigeracion.id_equipo == data.id_equipo).first()
    if not equipo:
        raise HTTPException(status_code=404, detail="Equipo refrigerante no encontrado")

    es_excursion = data.temperatura_c < float(equipo.temp_min) or data.temperatura_c > float(equipo.temp_max)

    registro = RegistroTemperatura(
        id_equipo=equipo.id_equipo,
        id_usuario=current["usuario"].id_usuario,
        temperatura_c=data.temperatura_c,
        es_excursion=es_excursion,
        observacion=data.observacion,
    )
    db.add(registro)
    db.flush()

    lotes_afectados = 0
    if es_excursion:
        equipo.estado_operativo = "ALERTA_CRITICA"
        lotes = db.query(Lote).filter(Lote.id_equipo == equipo.id_equipo, Lote.estado == "DISPONIBLE").all()
        for lote in lotes:
            lote.estado = "CUARENTENA"
            lotes_afectados += 1
        detalle = f"EXCURSIÓN TÉRMICA ({data.temperatura_c}°C) en {equipo.codigo_equipo}. {lotes_afectados} lotes bloqueados en CUARENTENA."
    else:
        equipo.estado_operativo = "NORMAL"
        detalle = f"Lectura normal ({data.temperatura_c}°C) en {equipo.codigo_equipo}."

    registrar_auditoria(db, current["usuario"].id_usuario, "LECTURA_TEMPERATURA", "registros_temperatura", registro.id_registro, detalle, request)
    db.commit()

    return {
        "mensaje": detalle,
        "es_excursion": es_excursion,
        "lotes_en_cuarentena": lotes_afectados,
    }

# RF05: Despacho automático bajo regla FEFO (Caso de Prueba CP-03)
@app.post("/api/lotes/despacho")
def despachar_fefo(
    data: DespachoFEFORequest,
    request: Request,
    current=Depends(require_roles(["ADMIN_QF", "OPERADOR_TENS"])),
    db: Session = Depends(get_db),
):
    lote = (
        db.query(Lote)
        .filter(
            Lote.id_insumo == data.id_insumo,
            Lote.estado == "DISPONIBLE",
            Lote.cantidad_actual >= data.cantidad,
            Lote.fecha_vencimiento >= date.today(),
        )
        .order_by(Lote.fecha_vencimiento.asc())
        .first()
    )

    if not lote:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No hay lotes disponibles vigentes (pueden estar agotados, vencidos o en CUARENTENA).",
        )

    lote.cantidad_actual -= data.cantidad
    if lote.cantidad_actual == 0:
        lote.estado = "AGOTADO"

    mov = MovimientoInventario(
        id_lote=lote.id_lote,
        id_usuario=current["usuario"].id_usuario,
        tipo_movimiento="DESPACHO_FEFO",
        cantidad=data.cantidad,
        observacion=data.observacion,
    )
    db.add(mov)
    registrar_auditoria(
        db,
        current["usuario"].id_usuario,
        "DESPACHO_FEFO",
        "lotes",
        lote.id_lote,
        f"Despacho FEFO de {data.cantidad} unid. del lote {lote.codigo_lote} (vence {lote.fecha_vencimiento})",
        request,
    )
    db.commit()

    return {
        "mensaje": "Despacho realizado exitosamente bajo regla FEFO",
        "lote_seleccionado": lote.codigo_lote,
        "fecha_vencimiento": str(lote.fecha_vencimiento),
        "stock_restante": lote.cantidad_actual,
    }

# RF06: Liberar lote en cuarentena o aprobar merma (Solo Químico Farmacéutico - Caso de Prueba CP-01)
@app.post("/api/lotes/liberar")
def gestionar_cuarentena(
    data: LiberarCuarentenaRequest,
    request: Request,
    current=Depends(require_roles(["ADMIN_QF"])),
    db: Session = Depends(get_db),
):
    lote = db.query(Lote).filter(Lote.id_lote == data.id_lote).first()
    if not lote or lote.estado != "CUARENTENA":
        raise HTTPException(status_code=400, detail="El lote no existe o no está en cuarentena")

    nuevo_estado = "DISPONIBLE" if data.accion == "LIBERAR" else "MERMA"
    lote.estado = nuevo_estado
    if nuevo_estado == "MERMA":
        lote.cantidad_actual = 0

    registrar_auditoria(
        db,
        current["usuario"].id_usuario,
        f"CUARENTENA_{data.accion}",
        "lotes",
        lote.id_lote,
        f"Lote {lote.codigo_lote} pasó a {nuevo_estado}. Motivo: {data.observacion}",
        request,
    )
    db.commit()
    return {"mensaje": f"Lote {lote.codigo_lote} actualizado a {nuevo_estado}"}

# RF07: Consulta de bitácora de auditoría inmutable
@app.get("/api/auditoria")
def ver_auditoria(current=Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(AuditoriaLog).order_by(AuditoriaLog.id_log.desc()).limit(100).all()