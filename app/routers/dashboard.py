from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.scan import Scan


router = APIRouter()

templates = Jinja2Templates(
    directory="app/templates"
)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db)
):

    total_scans = db.query(Scan).count()

    completed = db.query(Scan).filter(
        Scan.status=="Completed"
    ).count()

    running = db.query(Scan).filter(
        Scan.status=="Running"
    ).count()


    latest_scan = db.query(Scan).order_by(
        Scan.id.desc()
    ).first()


    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request":request,
            "total_scans":total_scans,
            "completed":completed,
            "running":running,
            "latest_scan":latest_scan
        }
    )