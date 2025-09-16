from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import datetime
from scanner import scan_host

import uvicorn
import datetime
import uuid
import asyncio
import random

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan storage
scans = {}

# helper to simulate port discovery and vulnerability identification
def _simulate_ports_and_vulns(target: str, scan_type: str):
    base = sum(ord(c) for c in target) % 100
    common_ports = [22, 80, 443, 3306, 8080, 53, 21, 23]
    count = 3 + (base % 6)
    random.shuffle(common_ports)
    open_ports = common_ports[:min(len(common_ports), count)]

    vulns = []
    for p in open_ports:
        if p in (22, 443):
            severity = random.choice(["low", "medium"])
        elif p in (80, 8080):
            severity = random.choice(["medium", "high"])
        else:
            severity = random.choice(["low", "medium", "high"])

        cve_id = f"CVE-2025-{random.randint(1000,9999)}"
        vulns.append({
            "id": cve_id,
            "severity": severity,
            "port": p,
            "description": f"Sample vulnerability affecting service on port {p} (simulated)."
        })

    return open_ports, vulns

# Background scan runner
async def run_scan(scan_id: str, target: str, scan_type: str = "Quick"):
    scans[scan_id]["status"] = "running"
    total_steps = 3 if scan_type == "Quick" else 6
    for i in range(total_steps):
        await asyncio.sleep(1 + random.random()*1.5)
        scans[scan_id]["progress"] = int(((i+1)/total_steps)*80)

    open_ports, vulns = _simulate_ports_and_vulns(target, scan_type)
    scans[scan_id]["results"] = {
        "open_ports": open_ports,
        "vulnerabilities": vulns
    }
    scans[scan_id]["status"] = "completed"
    scans[scan_id]["completed_at"] = datetime.datetime.utcnow().isoformat()

@app.post("/start_scan")
async def start_scan(target: str, background_tasks: BackgroundTasks, scan_type: str = "Quick"):
    target = target.strip(
    )
    print(target)
    if not target:
        return {"error": "target required"}

    # scan_id = str(uuid.uuid4())
    # now = datetime.datetime.utcnow().isoformat()
    # scans[scan_id] = {
    #     "id": scan_id,
    #     "target": target,
    #     "type": scan_type,
    #     "status": "queued",
    #     "created_at": now,
    #     "results": {},
    #     "progress": 0
    # }
    # background_tasks.add_task(run_scan, scan_id, target, scan_type)
    res =  scan_host(target)

    print(res,flush=True)
    return res


@app.get("/scan_status/{scan_id}")
async def scan_status(scan_id: str):
   
    return scans.get(scan_id, {"error": "not found"})


@app.get("/list_scans")
async def list_scans():
    items = list(scans.values())
    items.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    # Ensure all datetime-like fields are strings
    safe_items = []
    for s in items:
        s_copy = s.copy()
        # example: if created_at is a datetime object, convert it
        ca = s_copy.get("created_at")
        if isinstance(ca, (datetime.datetime,)):
            s_copy["created_at"] = ca.isoformat()
        safe_items.append(s_copy)

    return JSONResponse({"success": True, "count": len(safe_items), "scans": safe_items})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
