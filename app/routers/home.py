from fastapi import APIRouter, Request, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.scan import Scan
from app.utils.parser import parse_nmap_output

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


@router.get("/")
async def home(
    request: Request,
    db: Session = Depends(get_db)
):

    scans = db.query(Scan).order_by(
        Scan.id.desc()
    ).all()

    total_scans = len(scans)

    completed = sum(
        1 for s in scans if s.status == "Completed"
    )

    high_count = 0

    for scan in scans:

        if scan.output:

            findings = parse_nmap_output(scan.output)

            high_count += sum(
                1 for f in findings
                if f["severity"] == "High"
            )

    recent = scans[:5]

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "total_scans": total_scans,
            "completed": completed,
            "high_count": high_count,
            "recent": recent
        }
    )