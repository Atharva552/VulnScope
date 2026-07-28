from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

import os

from app.database.session import get_db
from app.models.scan import Scan

from app.utils.target import clean_target
from app.utils.security_headers import check_security_headers

from app.scanner.nmap_scanner import run_nmap
from app.scanner.ssl_checker import get_ssl_info

from app.utils.parser import parse_nmap_output
from app.utils.pdf_generator import generate_pdf


router = APIRouter(
    prefix="/scan",
    tags=["Scanner"]
)


templates = Jinja2Templates(
    directory="app/templates"
)



# =====================================
# WEB SCAN
# =====================================

@router.post("/web", response_class=HTMLResponse)
async def web_scan(
    request: Request,
    target: str = Form(...),
    scan_profile: str = Form("service"),
    db: Session = Depends(get_db)
):

    host, port = clean_target(target)

    scan = Scan(
        target=host,
        scan_type=scan_profile.title(),
        status="Running"
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    output = run_nmap(
    target=host,
    port=port,
    profile="service"
)

    scan.output = output
    scan.status = "Completed"

    db.commit()

    findings = parse_nmap_output(output)

    ssl_info = get_ssl_info(host)

    headers = check_security_headers(target)

    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context={
            "request": request,
            "target": host,
            "output": output,
            "findings": findings,
            "ssl_info": ssl_info,
            "headers": headers
        }
    )




# =====================================
# VIEW SCAN
# =====================================

@router.get(
    "/view/{scan_id}",
    response_class=HTMLResponse
)

async def view_scan(
    scan_id:int,
    request:Request,
    db:Session=Depends(get_db)
):


    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()



    if not scan:

        return RedirectResponse(
            "/",
            status_code=303
        )



    findings = parse_nmap_output(
        scan.output
    )


    ssl_info = get_ssl_info(
        scan.target
    )


    headers = check_security_headers(
        scan.target
    )



    high = sum(
        1 for f in findings
        if f["severity"]=="High"
    )


    medium = sum(
        1 for f in findings
        if f["severity"]=="Medium"
    )


    low = sum(
        1 for f in findings
        if f["severity"]=="Low"
    )



    return templates.TemplateResponse(

        request=request,

        name="view.html",

        context={

            "request":request,

            "scan":scan,

            "findings":findings,

            "ssl_info":ssl_info,

            "headers":headers,

            "high":high,

            "medium":medium,

            "low":low
        }

    )





# =====================================
# HISTORY PAGE
# =====================================

@router.get(
    "/history-page",
    response_class=HTMLResponse
)

async def history_page(
    request:Request,
    db:Session=Depends(get_db)
):


    scans = db.query(Scan)\
        .order_by(Scan.id.desc())\
        .all()



    return templates.TemplateResponse(

        request=request,

        name="history.html",

        context={

            "request":request,

            "scans":scans

        }

    )





# =====================================
# DELETE SCAN
# =====================================

@router.get("/delete/{scan_id}")

def delete_scan(

    scan_id:int,

    db:Session=Depends(get_db)

):


    scan=db.query(Scan).filter(
        Scan.id==scan_id
    ).first()



    if scan:

        db.delete(scan)

        db.commit()



    return RedirectResponse(
        "/scan/history-page",
        status_code=303
    )





# =====================================
# REPORT PAGE
# =====================================

@router.get(
    "/report/{scan_id}",
    response_class=HTMLResponse
)

async def report_page(

    scan_id:int,

    request:Request,

    db:Session=Depends(get_db)

):


    scan=db.query(Scan).filter(
        Scan.id==scan_id
    ).first()



    if not scan:

        return RedirectResponse(
            "/",
            status_code=303
        )



    findings=parse_nmap_output(
        scan.output
    )


    ssl_info=get_ssl_info(
        scan.target
    )


    headers=check_security_headers(
        scan.target
    )



    high=sum(
        1 for f in findings
        if f["severity"]=="High"
    )


    medium=sum(
        1 for f in findings
        if f["severity"]=="Medium"
    )


    low=sum(
        1 for f in findings
        if f["severity"]=="Low"
    )



    return templates.TemplateResponse(

        request=request,

        name="report.html",

        context={

            "request":request,

            "scan":scan,

            "findings":findings,

            "ssl_info":ssl_info,

            "headers":headers,

            "high":high,

            "medium":medium,

            "low":low

        }

    )





# =====================================
# PDF DOWNLOAD
# =====================================

@router.get("/pdf/{scan_id}")

async def download_pdf(

    scan_id:int,

    db:Session=Depends(get_db)

):


    scan=db.query(Scan).filter(
        Scan.id==scan_id
    ).first()



    if not scan:

        return RedirectResponse(
            "/",
            status_code=303
        )



    findings=parse_nmap_output(
        scan.output
    )


    ssl_info=get_ssl_info(
        scan.target
    )


    headers=check_security_headers(
        scan.target
    )



    os.makedirs(
        "reports",
        exist_ok=True
    )



    filename=f"reports/VAPT_Report_{scan.id}.pdf"



    generate_pdf(

        scan,

        findings,

        filename,

        ssl_info,

        headers

    )



    if not os.path.exists(filename):

        return {
            "error":"PDF generation failed"
        }



    return FileResponse(

        filename,

        media_type="application/pdf",

        filename=f"VAPT_Report_{scan.id}.pdf"

    )

from fastapi.responses import JSONResponse


# =====================================
# DOWNLOAD JSON
# =====================================

import json
from fastapi.responses import Response


@router.get("/json/{scan_id}")
async def download_json(
    scan_id: int,
    db: Session = Depends(get_db)
):

    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        return RedirectResponse(
            "/",
            status_code=303
        )

    findings = parse_nmap_output(
        scan.output
    )

    ssl_info = get_ssl_info(
        scan.target
    )

    headers = check_security_headers(
        scan.target
    )

    json_data = {
        "scan_id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "ssl": ssl_info,
        "headers": headers,
        "findings": findings,
        "raw_output": scan.output
    }

    return Response(
        content=json.dumps(json_data, indent=4),
        media_type="application/json",
        headers={
            "Content-Disposition":
            f'attachment; filename="VAPT_Report_{scan.id}.json"'
        }
    )



# =====================================
# API SCAN
# KEEP LAST
# =====================================

@router.get("/{target}")

def scan_target(

    target:str,

    db:Session=Depends(get_db)

):


    host, port = clean_target(target)



    scan=Scan(

        target=host,

        scan_type="Nmap",

        status="Running"

    )


    db.add(scan)

    db.commit()

    db.refresh(scan)



    output = run_nmap(
    target=host,
    port=port,
    profile="service"
)


    scan.output=output

    scan.status="Completed"



    db.commit()



    return {

        "scan_id":scan.id,

        "target": host,

        "status":scan.status,

        "output":output

    }