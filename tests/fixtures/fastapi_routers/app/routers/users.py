from fastapi import APIRouter

router = APIRouter(prefix="/api")


@router.get("/users/{id}")
def get_user(id: int, active: bool = True):
    return {"id": id, "active": active}
