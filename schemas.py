from datetime import date
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)

class TemperaturaCreate(BaseModel):
    id_equipo: int
    temperatura_c: float = Field(..., ge=-50.0, le=60.0)
    observacion: Optional[str] = None

class LoteCreate(BaseModel):
    id_insumo: int
    id_equipo: Optional[int] = None
    codigo_lote: str = Field(..., min_length=2, max_length=50)
    fecha_vencimiento: date
    cantidad_inicial: int = Field(..., gt=0)

class DespachoFEFORequest(BaseModel):
    id_insumo: int
    cantidad: int = Field(..., gt=0)
    observacion: Optional[str] = "Despacho clínico bajo regla FEFO"

class LiberarCuarentenaRequest(BaseModel):
    id_lote: int
    accion: str = Field(..., pattern="^(LIBERAR|MERMA)$")
    observacion: str = Field(..., min_length=5)