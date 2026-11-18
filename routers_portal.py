import io
import csv
import ssl
import sys
import json
import socket
import secrets
import hashlib
from html import escape as html_escape
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# Resolve main module cleanly whether imported via `uvicorn main:app` or `python routers_portal.py --test`
_m = sys.modules.get("main") or sys.modules.get("__main__")
if not _m or not hasattr(_m, "SessionLocal"):
    import main as _m

API_V1_PREFIX = _m.API_V1_PREFIX
SessionLocal = _m.SessionLocal
get_db = _m.get_db
utcnow = _m.utcnow
encrypt_secret = _m.encrypt_secret
decrypt_secret = _m.decrypt_secret
write_audit = _m.write_audit
require_tenant_perm = _m.require_tenant_perm
TenantContext = _m.TenantContext

ISPTenant = _m.ISPTenant
Branch = _m.Branch
MikroTikRouter = _m.MikroTikRouter
RouterCredential = _m.RouterCredential
RouterConfiguration = _m.RouterConfiguration
InternetPackage = _m.InternetPackage
Customer = _m.Customer
NetworkSession = _m.NetworkSession
Voucher = _m.Voucher
VoucherRedemption = _m.VoucherRedemption
ISPPaymentConfig = _m.ISPPaymentConfig

router = APIRouter()

# ==========================================================
# STAGE 7: UNIVERSAL MIKROTIK MODEL & COMPATIBILITY MATRIX
# ==========================================================

MIKROTIK_MODELS = {
    "hAP lite": {"arch": "smips", "min_ram_mb": 32, "ros": ["6"], "note": "Low RAM (32MB); use lean Hotspot or external RADIUS. Avoid heavy queues."},
    "hAP mini": {"arch": "smips", "min_ram_mb": 32, "ros": ["6"], "note": "Low RAM (32MB); avoid RouterOS 7 upgrade and large local user tables."},
    "hAP ac": {"arch": "mipsbe", "min_ram_mb": 128, "ros": ["6", "7"], "note": "Suitable for small-to-medium Hotspot/PPPoE."},
    "hAP ac2": {"arch": "arm", "min_ram_mb": 128, "ros": ["6", "7"], "note": "Strong ARM CPU; great for Hotspot + PPPoE."},
    "hAP ac3": {"arch": "arm", "min_ram_mb": 256, "ros": ["6", "7"], "note": "Full Hotspot, PPPoE, API & RADIUS support."},
    "hAP ax series": {"arch": "arm64", "min_ram_mb": 256, "ros": ["7"], "note": "RouterOS 7 native; supports WiFiWave2 + full billing."},
    "RB750 series": {"arch": "mipsbe", "min_ram_mb": 64, "ros": ["6", "7"], "note": "Entry router; recommended max ~80 concurrent users."},
    "RB750Gr3": {"arch": "mmips", "min_ram_mb": 256, "ros": ["6", "7"], "note": "Excellent hEX value router for Hotspot & PPPoE."},
    "RB951 series": {"arch": "mipsbe", "min_ram_mb": 128, "ros": ["6", "7"], "note": "Good branch Hotspot router."},
    "RB2011 series": {"arch": "mipsbe/arm", "min_ram_mb": 128, "ros": ["6", "7"], "note": "Legacy; keep queues moderate for >100 users."},
    "RB3011 series": {"arch": "arm", "min_ram_mb": 1024, "ros": ["6", "7"], "note": "Dual-core ARM; solid Hotspot & PPPoE."},
    "RB4011 series": {"arch": "arm", "min_ram_mb": 1024, "ros": ["6", "7"], "note": "High-capacity quad-core ISP router."},
    "RB5009 series": {"arch": "arm64", "min_ram_mb": 1024, "ros": ["7"], "note": "Enterprise RouterOS 7 high-throughput gateway."},
    "CCR series": {"arch": "tile/arm64", "min_ram_mb": 2048, "ros": ["6", "7"], "note": "Carrier-grade core router for large PPPoE/Hotspot."},
    "CRS series": {"arch": "mipsbe/arm", "min_ram_mb": 128, "ros": ["6", "7"], "note": "Switch-first hardware: heavy NAT/Hotspot/PPPoE is CPU-bound; pair with RB5009/CCR for >50 users."},
    "CHR": {"arch": "x86_64/arm64", "min_ram_mb": 256, "ros": ["6", "7"], "note": "Cloud Hosted Router; ideal for central PPPoE/VPN/RADIUS."},
}


def evaluate_compatibility(model: str, ros_version: str, free_mem_bytes: int | None = None, packages: list[str] | None = None, interfaces: list[str] | None = None, api_ok: bool = False) -> dict:
    warnings, alternatives = [], []
    major_ros = "7" if str(ros_version).strip().startswith("7") else ("6" if str(ros_version).strip().startswith("6") else "unknown")
    pkgs = {p.lower() for p in (packages or [])}
    model_lower = (model or "").lower()

    if "crs" in model_lower:
        warnings.append("CRS devices are switches with limited CPU for NAT/Hotspot/PPPoE.")
        alternatives.append("Offload Hotspot/PPPoE termination to RB750Gr3, RB4011, RB5009, or CCR.")
    if "hap lite" in model_lower or "hap mini" in model_lower or (free_mem_bytes is not None and free_mem_bytes < 16 * 1024 * 1024):
        warnings.append("Low memory detected; avoid large local user databases.")
        alternatives.append("Use RADIUS authentication or limit local Hotspot users.")
    if major_ros == "6" and "ax" in model_lower:
        warnings.append("hAP ax requires RouterOS 7.")

    hotspot_ok = ("hotspot" in pkgs) or ("routeros" in pkgs) or (not pkgs and api_ok)
    ppp_ok = ("ppp" in pkgs) or ("routeros" in pkgs) or (not pkgs and api_ok)
    radius_ok = api_ok or major_ros in ("6", "7")

    return {
        "api_available": api_ok,
        "routeros_major": major_ros,
        "hotspot_supported": hotspot_ok,
        "ppp_supported": ppp_ok,
        "radius_supported": radius_ok,
        "interfaces_count": len(interfaces or []),
        "interfaces": (interfaces or [])[:25],
        "warnings": warnings,
        "alternatives": alternatives,
        "compatible": bool(api_ok and (hotspot_ok or ppp_ok)),
    }


# ==========================================================
# STAGE 8: PURE-PYTHON MIKROTIK ROUTEROS BINARY API CLIENT
# ==========================================================

class RouterOSClient:
    def __init__(self, host: str, port: int = 8728, use_ssl: bool = False, timeout: float = 5.0):
        self.host = host
        self.port = int(port)
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.sock = None

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self.sock = raw

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _encode_len(self, length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        if length < 0x4000:
            v = length | 0x8000
            return v.to_bytes(2, "big")
        if length < 0x200000:
            v = length | 0xC00000
            return v.to_bytes(3, "big")
        if length < 0x10000000:
            v = length | 0xE0000000
            return v.to_bytes(4, "big")
        return b"\xF0" + length.to_bytes(4, "big")

    def _read_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Router closed connection")
            buf.extend(chunk)
        return bytes(buf)

    def _read_len(self) -> int:
        b = self._read_exact(1)[0]
        if (b & 0x80) == 0:
            return b
        if (b & 0xC0) == 0x80:
            return ((b & ~0xC0) << 8) + self._read_exact(1)[0]
        if (b & 0xE0) == 0xC0:
            return ((b & ~0xE0) << 16) + int.from_bytes(self._read_exact(2), "big")
        if (b & 0xF0) == 0xE0:
            return ((b & ~0xF0) << 24) + int.from_bytes(self._read_exact(3), "big")
        return int.from_bytes(self._read_exact(4), "big")

    def send_sentence(self, words: list[str]):
        payload = bytearray()
        for w in words:
            wb = w.encode("utf-8")
            payload.extend(self._encode_len(len(wb)))
            payload.extend(wb)
        payload.append(0)
        self.sock.sendall(bytes(payload))

    def read_sentence(self) -> list[str]:
        words = []
        while True:
            ln = self._read_len()
            if ln == 0:
                return words
            words.append(self._read_exact(ln).decode("utf-8", errors="replace"))

    def talk(self, words: list[str]) -> list[dict]:
        self.send_sentence(words)
        rows = []
        while True:
            sent = self.read_sentence()
            if not sent:
                continue
            tag = sent[0]
            attrs = {}
            for w in sent[1:]:
                if w.startswith("=") and "=" in w[1:]:
                    k, v = w[1:].split("=", 1)
                    attrs[k] = v
            if tag == "!re":
                rows.append(attrs)
            elif tag == "!done":
                if attrs:
                    rows.append(attrs)
                return rows
            elif tag in ("!trap", "!fatal"):
                raise RuntimeError(attrs.get("message") or f"RouterOS error: {sent}")

    def login(self, username: str, password: str):
        res = self.talk(["/login", f"=name={username}", f"=password={password}"])
        if res and "ret" in res[0]:
            chal = bytes.fromhex(res[0]["ret"])
            digest = hashlib.md5(b"\x00" + password.encode("utf-8") + chal).hexdigest()
            self.talk(["/login", f"=name={username}", f"=response=00{digest}"])


def probe_mikrotik_router(host: str, port: int, use_ssl: bool, username: str, password: str) -> dict:
    cli = RouterOSClient(host, port, use_ssl=use_ssl, timeout=5.0)
    try:
        cli.connect()
        cli.login(username, password)
        ident = (cli.talk(["/system/identity/print"]) or [{}])[0].get("name", "")
        res = (cli.talk(["/system/resource/print"]) or [{}])[0]
        ifaces = [r.get("name", "") for r in cli.talk(["/interface/print"]) if r.get("name")]
        pkgs = [r.get("name", "") for r in cli.talk(["/system/package/print"]) if r.get("name") and r.get("disabled", "false") != "true"]
        free_mem = int(res.get("free-memory", 0) or 0)
        comp = evaluate_compatibility(
            model=res.get("board-name", ""),
            ros_version=res.get("version", ""),
            free_mem_bytes=free_mem,
            packages=pkgs,
            interfaces=ifaces,
            api_ok=True,
        )
        return {
            "online": True,
            "identity": ident,
            "hardware_model": res.get("board-name", "Unknown"),
            "routeros_version": res.get("version", "Unknown"),
            "architecture": res.get("architecture-name", "Unknown"),
            "cpu": f"{res.get('cpu', '')} ({res.get('cpu-count', '1')} cores)",
            "free_memory_bytes": free_mem,
            "total_memory_bytes": int(res.get("total-memory", 0) or 0),
            "uptime": res.get("uptime", ""),
            "compatibility": comp,
        }
    except Exception as exc:
        return {"online": False, "error": str(exc), "compatibility": evaluate_compatibility("", "", api_ok=False)}
    finally:
        cli.close()


# ==========================================================
# STAGE 9: UNIVERSAL ROUTEROS SCRIPT GENERATOR (v6 & v7)
# ==========================================================

def generate_mikrotik_script(router_name: str, model: str, ros_version: str, mode: str, hotspot_iface: str, pppoe_iface: str, server_url: str, radius_secret: str = "") -> str:
    v7 = str(ros_version).strip().startswith("7")
    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "-", router_name).strip("-") or "prime-gw"
    walled_cmd = (
        f'/ip hotspot walled-garden ip add dst-host="{server_url.replace("https://", "").replace("http://", "").split("/")[0]}" action=accept comment="PRIME-HOTSPOT-BILLING"'
    )
    lines = [
        f"# ============================================================",
        f"# PRIME HOTSPOT BILLING — NON-DESTRUCTIVE ROUTEROS v{'7' if v7 else '6'} SCRIPT",
        f"# Target Model: {model} | Mode: {mode} | Router: {safe_name}",
        f"# ============================================================",
        "",
        "# 1. MANDATORY PRE-INSTALL BACKUP (DO NOT SKIP)",
        "/system backup save name=prime-hotspot-preinstall",
        "/export file=prime-hotspot-preinstall",
        "",
        "# 2. WALLED GARDEN FOR CAPTIVE PORTAL",
        walled_cmd,
        "",
    ]
    if mode in ("API", "SCRIPT"):
        lines += [
            "# 3. NON-DESTRUCTIVE BILLING API SERVICE ACCOUNT",
            '/user group add name=prime-billing-grp policy=read,write,api,test comment="Prime Hotspot Billing"',
            ':if ([:len [/user find name="primebilling"]] = 0) do={ /user add name="primebilling" group=prime-billing-grp password="CHANGE_ME_STRONG_PASS" comment="Prime Billing API" }',
            "/ip service set api disabled=no port=8728",
            "",
        ]
    if mode == "RADIUS" or radius_secret:
        srv_host = server_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        lines += [
            "# 4. RADIUS AUTHENTICATION & ACCOUNTING",
            f'/radius add service=hotspot,ppp address={srv_host} secret="{radius_secret or "CHANGE_RADIUS_SECRET"}" timeout=3000ms comment="Prime Hotspot RADIUS"',
            "/ip hotspot profile set [find] use-radius=yes",
            "/ppp aaa set use-radius=yes accounting=yes",
            "",
        ]
    lines += [
        f"# 5. HOTSPOT & PPPOE INTERFACES CHECK ({hotspot_iface} / {pppoe_iface})",
        f':put ("Verify interfaces exist: {hotspot_iface}, {pppoe_iface}")',
        "/interface print brief",
        "",
        "# 6. VERIFY & TEST BILLING CONNECTIVITY",
        f'/tool fetch url="{server_url.rstrip("/")}/health" mode=https keep-result=no' if server_url.startswith("https://") else f'/tool fetch url="{server_url.rstrip("/")}/health" keep-result=no',
        "",
        "# ROLLBACK INSTRUCTIONS (IF NEEDED):",
        "# /system backup load name=prime-hotspot-preinstall",
    ]
    return "\n".join(lines)


# ==========================================================
# REQUEST SCHEMAS
# ==========================================================

class RouterIn(BaseModel):
    name: str
    host: str
    api_port: int = 8728
    use_ssl: bool = False
    integration_mode: str = "API"
    username: str = "primebilling"
    password: str = ""
    radius_secret: str = ""
    branch_id: str | None = None


class ScriptGenIn(BaseModel):
    model: str = "RB750Gr3"
    ros_version: str = "7"
    mode: str = "API"
    hotspot_interface: str = "bridge-hotspot"
    pppoe_interface: str = "ether2"
    server_url: str = "https://api.primehotspot.example"


class CustomerIn(BaseModel):
    full_name: str
    phone: str
    connection_type: str = "HOTSPOT"
    package_id: str
    router_id: str | None = None
    username: str = ""
    password: str = ""


class VoucherBatchIn(BaseModel):
    package_id: str
    quantity: int = Field(ge=1, le=500, default=10)
    prefix: str = "PH-"
    max_uses: int = Field(ge=1, le=20, default=1)
    valid_days: int = Field(ge=1, le=365, default=30)
    agent_staff_id: str | None = None


class VoucherRedeemIn(BaseModel):
    code: str
    phone: str = ""
    mac_address: str = ""


class ReconnectIn(BaseModel):
    identifier: str  # phone, account_number, or username


# ==========================================================
# ROUTER, COMPATIBILITY & SCRIPT ENDPOINTS (STAGES 7–9)
# ==========================================================

@router.get(f"{API_V1_PREFIX}/isp/compatibility-models")
def list_supported_models(ctx: TenantContext = Depends(require_tenant_perm("routers:read"))):
    return {"supported_models": MIKROTIK_MODELS, "future_devices": "Any RouterOS 6 or 7 device with API/Hotspot/PPP/RADIUS supported via live capability probe."}


@router.get(f"{API_V1_PREFIX}/isp/routers")
def list_routers(ctx: TenantContext = Depends(require_tenant_perm("routers:read")), db: Session = Depends(get_db)):
    rows = db.query(MikroTikRouter).filter(MikroTikRouter.tenant_id == ctx.tenant.id).all()
    return [
        {
            "id": r.id, "name": r.name, "host": r.host, "api_port": r.api_port,
            "integration_mode": r.integration_mode, "hardware_model": r.hardware_model,
            "routeros_version": r.routeros_version, "identity": r.identity,
            "status": r.status, "capabilities": json.loads(r.capabilities_json or "{}"),
        }
        for r in rows
    ]


@router.post(f"{API_V1_PREFIX}/isp/routers")
def add_router(body: RouterIn, ctx: TenantContext = Depends(require_tenant_perm("routers:write")), db: Session = Depends(get_db)):
    if ctx.plan and db.query(MikroTikRouter).filter(MikroTikRouter.tenant_id == ctx.tenant.id).count() >= ctx.plan.max_routers:
        raise HTTPException(status_code=403, detail="Plan router limit reached")
    mode = body.integration_mode.upper()
    if mode == "API" and ctx.plan and not ctx.plan.allow_api:
        raise HTTPException(status_code=403, detail="Current SaaS plan does not include RouterOS API; use SCRIPT mode or upgrade")
    r = MikroTikRouter(
        tenant_id=ctx.tenant.id, branch_id=body.branch_id, name=body.name.strip(),
        host=body.host.strip(), api_port=body.api_port, use_ssl=body.use_ssl, integration_mode=mode,
    )
    db.add(r)
    db.flush()
    db.add(RouterCredential(
        tenant_id=ctx.tenant.id, router_id=r.id,
        username_enc=encrypt_secret(body.username), password_enc=encrypt_secret(body.password),
        radius_secret_enc=encrypt_secret(body.radius_secret),
    ))
    write_audit(db, "STAFF", ctx.actor_id, "ADD_ROUTER", tenant_id=ctx.tenant.id, details=r.name)
    db.commit()
    return {"id": r.id, "name": r.name, "status": r.status}


@router.post(f"{API_V1_PREFIX}/isp/routers/{{router_id}}/test")
def test_router_connection(router_id: str, ctx: TenantContext = Depends(require_tenant_perm("routers:write")), db: Session = Depends(get_db)):
    r = db.query(MikroTikRouter).filter(MikroTikRouter.id == router_id, MikroTikRouter.tenant_id == ctx.tenant.id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Router not found")
    cred = db.query(RouterCredential).filter(RouterCredential.router_id == r.id, RouterCredential.tenant_id == ctx.tenant.id).first()
    if not cred:
        raise HTTPException(status_code=400, detail="Router credentials missing")
    probe = probe_mikrotik_router(r.host, r.api_port, r.use_ssl, decrypt_secret(cred.username_enc), decrypt_secret(cred.password_enc))
    if probe["online"]:
        r.status = "ONLINE"
        r.identity = probe["identity"]
        r.hardware_model = probe["hardware_model"]
        r.routeros_version = probe["routeros_version"]
        r.architecture = probe["architecture"]
        r.capabilities_json = json.dumps(probe["compatibility"])
        r.last_seen_at = utcnow()
    else:
        r.status = "OFFLINE"
        r.capabilities_json = json.dumps(probe["compatibility"])
    db.commit()
    return probe


@router.post(f"{API_V1_PREFIX}/isp/routers/{{router_id}}/script")
def create_router_script(router_id: str, body: ScriptGenIn, ctx: TenantContext = Depends(require_tenant_perm("routers:write")), db: Session = Depends(get_db)):
    r = db.query(MikroTikRouter).filter(MikroTikRouter.id == router_id, MikroTikRouter.tenant_id == ctx.tenant.id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Router not found")
    cred = db.query(RouterCredential).filter(RouterCredential.router_id == r.id).first()
    rad_sec = decrypt_secret(cred.radius_secret_enc) if cred else ""
    script = generate_mikrotik_script(r.name, body.model, body.ros_version, body.mode.upper(), body.hotspot_interface, body.pppoe_interface, body.server_url, rad_sec)
    cfg = RouterConfiguration(tenant_id=ctx.tenant.id, router_id=r.id, config_type="GENERATED_SCRIPT", script_body=script)
    db.add(cfg)
    db.commit()
    return {"config_id": cfg.id, "model": body.model, "ros_version": body.ros_version, "script": script}


@router.get(f"{API_V1_PREFIX}/isp/routers/{{router_id}}/script/download", response_class=PlainTextResponse)
def download_latest_script(router_id: str, ctx: TenantContext = Depends(require_tenant_perm("routers:read")), db: Session = Depends(get_db)):
    cfg = db.query(RouterConfiguration).filter(RouterConfiguration.router_id == router_id, RouterConfiguration.tenant_id == ctx.tenant.id, RouterConfiguration.config_type == "GENERATED_SCRIPT").order_by(RouterConfiguration.created_at.desc()).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="No generated script found")
    return PlainTextResponse(cfg.script_body, headers={"Content-Disposition": f'attachment; filename="prime-{router_id[:8]}.rsc"'})


# ==========================================================
# HOTSPOT & PPPOE CUSTOMERS (STAGES 10 & 17)
# ==========================================================

def _provision_customer_on_router(db: Session, r: MikroTikRouter | None, customer: Customer, pkg: InternetPackage, plain_secret: str) -> str:
    if not r or r.integration_mode != "API" or r.status != "ONLINE":
        return "QUEUED_FOR_SYNC"
    cred = db.query(RouterCredential).filter(RouterCredential.router_id == r.id).first()
    if not cred:
        return "QUEUED_FOR_SYNC"
    cli = RouterOSClient(r.host, r.api_port, r.use_ssl, timeout=4.0)
    try:
        cli.connect()
        cli.login(decrypt_secret(cred.username_enc), decrypt_secret(cred.password_enc))
        if customer.connection_type == "PPPOE":
            cli.talk(["/ppp/secret/add", f"=name={customer.username}", f"=password={plain_secret}", "=service=pppoe", f"=comment=PH:{customer.account_number}"])
        else:
            cli.talk(["/ip/hotspot/user/add", f"=name={customer.username}", f"=password={plain_secret}", f"=limit-uptime={pkg.duration_minutes}m", f"=comment=PH:{customer.account_number}"])
        return "PROVISIONED_ON_ROUTER"
    except Exception:
        return "SYNC_RETRY_NEEDED"
    finally:
        cli.close()


@router.get(f"{API_V1_PREFIX}/isp/customers")
def list_customers(search: str = Query(default=""), ctx: TenantContext = Depends(require_tenant_perm("customers:read")), db: Session = Depends(get_db)):
    q = db.query(Customer).filter(Customer.tenant_id == ctx.tenant.id)
    rows = q.order_by(Customer.created_at.desc()).limit(200).all()
    if search.strip():
        s = search.strip().lower()
        rows = [c for c in rows if s in c.full_name.lower() or s in c.phone.lower() or s in c.account_number.lower() or s in c.username.lower()]
    return [{"id": c.id, "account_number": c.account_number, "full_name": c.full_name, "phone": c.phone, "connection_type": c.connection_type, "username": c.username, "status": c.status, "expires_at": c.expires_at.isoformat() if c.expires_at else None} for c in rows]


@router.post(f"{API_V1_PREFIX}/isp/customers")
def create_customer(body: CustomerIn, ctx: TenantContext = Depends(require_tenant_perm("customers:write")), db: Session = Depends(get_db)):
    if ctx.plan and db.query(Customer).filter(Customer.tenant_id == ctx.tenant.id).count() >= ctx.plan.max_customers:
        raise HTTPException(status_code=403, detail="Plan customer limit reached")
    pkg = db.query(InternetPackage).filter(InternetPackage.id == body.package_id, InternetPackage.tenant_id == ctx.tenant.id).first()
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    ctype = body.connection_type.upper()
    if ctype == "PPPOE" and ctx.plan and not ctx.plan.allow_pppoe:
        raise HTTPException(status_code=403, detail="Current plan does not include PPPoE")

    acct = "PH" + secrets.token_hex(4).upper()
    uname = (body.username or acct).strip()
    pwd = (body.password or secrets.token_hex(4)).strip()
    r = db.query(MikroTikRouter).filter(MikroTikRouter.id == body.router_id, MikroTikRouter.tenant_id == ctx.tenant.id).first() if body.router_id else None
    cust = Customer(
        tenant_id=ctx.tenant.id, router_id=r.id if r else None, package_id=pkg.id,
        account_number=acct, full_name=body.full_name.strip(), phone=body.phone.strip(),
        connection_type=ctype, username=uname, secret_enc=encrypt_secret(pwd),
        status="ACTIVE", expires_at=utcnow() + timedelta(minutes=pkg.duration_minutes),
    )
    db.add(cust)
    db.flush()
    sync_status = _provision_customer_on_router(db, r, cust, pkg, pwd)
    write_audit(db, "STAFF", ctx.actor_id, "CREATE_CUSTOMER", tenant_id=ctx.tenant.id, details=acct)
    db.commit()
    return {"id": cust.id, "account_number": acct, "username": uname, "status": cust.status, "router_sync": sync_status}


@router.post(f"{API_V1_PREFIX}/isp/customers/{{customer_id}}/disconnect")
def disconnect_customer(customer_id: str, ctx: TenantContext = Depends(require_tenant_perm("customers:write")), db: Session = Depends(get_db)):
    c = db.query(Customer).filter(Customer.id == customer_id, Customer.tenant_id == ctx.tenant.id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Customer not found")
    c.status = "DISCONNECTED"
    db.query(NetworkSession).filter(NetworkSession.customer_id == c.id, NetworkSession.ended_at == None).update({"ended_at": utcnow()})
    write_audit(db, "STAFF", ctx.actor_id, "DISCONNECT_CUSTOMER", tenant_id=ctx.tenant.id, details=c.account_number)
    db.commit()
    return {"id": c.id, "status": c.status}


# ==========================================================
# STAGE 16: VOUCHER SYSTEM (BULK, EXPORT, ATOMIC REDEMPTION)
# ==========================================================

def _gen_voucher_code(prefix: str) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return (prefix.upper()[:10] + "".join(secrets.choice(alphabet) for _ in range(8)))


@router.post(f"{API_V1_PREFIX}/isp/vouchers/generate")
def generate_vouchers(body: VoucherBatchIn, ctx: TenantContext = Depends(require_tenant_perm("vouchers:write")), db: Session = Depends(get_db)):
    pkg = db.query(InternetPackage).filter(InternetPackage.id == body.package_id, InternetPackage.tenant_id == ctx.tenant.id).first()
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    exp = utcnow() + timedelta(days=body.valid_days)
    created = []
    for _ in range(body.quantity):
        code = _gen_voucher_code(body.prefix)
        while db.query(Voucher).filter(Voucher.tenant_id == ctx.tenant.id, Voucher.code == code).first():
            code = _gen_voucher_code(body.prefix)
        v = Voucher(tenant_id=ctx.tenant.id, package_id=pkg.id, code=code, agent_staff_id=body.agent_staff_id, max_uses=body.max_uses, expires_at=exp)
        db.add(v)
        created.append(code)
    write_audit(db, "STAFF", ctx.actor_id, "GENERATE_VOUCHERS", tenant_id=ctx.tenant.id, details=f"qty={len(created)}")
    db.commit()
    return {"generated": len(created), "package": pkg.name, "codes": created}


@router.get(f"{API_V1_PREFIX}/isp/vouchers")
def list_vouchers(status: str = Query(default=""), ctx: TenantContext = Depends(require_tenant_perm("vouchers:read")), db: Session = Depends(get_db)):
    q = db.query(Voucher).filter(Voucher.tenant_id == ctx.tenant.id)
    if status:
        q = q.filter(Voucher.status == status.upper())
    return [{"id": v.id, "code": v.code, "package_id": v.package_id, "uses_count": v.uses_count, "max_uses": v.max_uses, "status": v.status} for v in q.order_by(Voucher.created_at.desc()).limit(250).all()]


@router.get(f"{API_V1_PREFIX}/isp/vouchers/export/csv", response_class=PlainTextResponse)
def export_vouchers_csv(ctx: TenantContext = Depends(require_tenant_perm("vouchers:read")), db: Session = Depends(get_db)):
    rows = db.query(Voucher).filter(Voucher.tenant_id == ctx.tenant.id).order_by(Voucher.created_at.desc()).limit(500).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["code", "package_id", "status", "uses_count", "max_uses", "expires_at"])
    for v in rows:
        w.writerow([v.code, v.package_id, v.status, v.uses_count, v.max_uses, v.expires_at.isoformat() if v.expires_at else ""])
    return PlainTextResponse(buf.getvalue(), headers={"Content-Disposition": 'attachment; filename="vouchers.csv"'})


# ==========================================================
# STAGE 11: CAPTIVE PORTAL, VOUCHER REDEMPTION & RECONNECT
# ==========================================================

PORTAL_SHELL = """<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__BIZ__ — WiFi Portal</title>
<style>
  body{margin:0;font-family:system-ui,sans-serif;background:#070e23;color:#ffffff;padding:16px}
  .wrap{max-width:480px;margin:0 auto}
  .hdr{background:#0f1b3d;border:1px solid #10b981;border-radius:16px;padding:18px;text-align:center}
  .badge{display:inline-block;background:#10b981;color:#052e16;font-weight:800;font-size:11px;padding:4px 10px;border-radius:999px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px}
  .pkg{background:#0f1b3d;border:1px solid #1e3366;border-radius:14px;padding:14px;display:flex;flex-direction:column;justify-content:space-between}
  .price{font-size:20px;font-weight:800;color:#10b981;margin:6px 0}
  .btn{background:#10b981;color:#052e16;border:none;border-radius:10px;padding:10px;font-weight:800;width:100%;cursor:pointer;margin-top:8px}
  .box{background:#0f1b3d;border:1px solid #1e3366;border-radius:14px;padding:14px;margin-top:14px}
  input{width:100%;box-sizing:border-box;padding:10px;border-radius:10px;border:1px solid #2b4585;background:#070e23;color:#fff;margin-top:8px}
  .muted{color:#94a3b8;font-size:13px}
</style></head><body><div class="wrap">
  <div class="hdr"><span class="badge">HIGH-SPEED WIFI</span><h2 style="margin:8px 0 4px">__BIZ__</h2>
    <div class="muted">Customer Care: __PHONE__</div></div>
  <div class="grid">__CARDS__</div>
  <div class="box"><b>🎟️ Redeem Voucher</b>
    <input id="vc" placeholder="Enter voucher code (e.g. PH-XXXX)" />
    <input id="vp" placeholder="Phone number (07...)" />
    <button class="btn" onclick="redeem()">Activate Voucher</button><div id="vr" class="muted" style="margin-top:8px"></div>
  </div>
  <div class="box"><b>🔄 Reconnect / Check Account</b>
    <input id="rc" placeholder="Phone or Account No." />
    <button class="btn" onclick="reconn()">Check &amp; Reconnect</button><div id="rr" class="muted" style="margin-top:8px"></div>
  </div>
  <div class="box"><b>💳 Payment Instructions</b><div class="muted" style="margin-top:6px">__PAYINFO__</div></div>
</div>
<script>
const slug="__SLUG__";
async function redeem(){
  const r=await fetch('/api/v1/portal/'+slug+'/redeem-voucher',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:document.getElementById('vc').value,phone:document.getElementById('vp').value})});
  const d=await r.json();document.getElementById('vr').innerText=r.ok?('Active! User: '+d.username+' | Expires: '+d.expires_at):(d.detail||'Failed');
}
async function reconn(){
  const r=await fetch('/api/v1/portal/'+slug+'/reconnect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({identifier:document.getElementById('rc').value})});
  const d=await r.json();document.getElementById('rr').innerText=r.ok?(d.status+' | Expires: '+d.expires_at):(d.detail||'Not found');
}
</script></body></html>"""


@router.get("/portal/{slug}", response_class=HTMLResponse)
def captive_portal(slug: str, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.slug == slug.lower().strip()).first()
    if not t:
        raise HTTPException(status_code=404, detail="ISP portal not found")
    pkgs = db.query(InternetPackage).filter(InternetPackage.tenant_id == t.id, InternetPackage.service_type == "HOTSPOT", InternetPackage.is_visible == True).order_by(InternetPackage.price).all()
    cfgs = db.query(ISPPaymentConfig).filter(ISPPaymentConfig.tenant_id == t.id, ISPPaymentConfig.is_active == True).all()

    cards = ""
    for p in pkgs:
        hrs = round(p.duration_minutes / 60, 1)
        dur_lbl = f"{int(hrs)} Hours" if hrs < 24 else f"{round(hrs / 24, 1)} Days"
        cards += f'<div class="pkg"><div><b>{html_escape(p.name)}</b><div class="muted">{dur_lbl} • {p.device_limit} device(s)</div><div class="price">{html_escape(t.currency)} {float(p.price):,.0f}</div></div><button class="btn" onclick="alert(\'Select payment in Milestone 4 or redeem voucher below\')">Buy Now</button></div>'
    if not cards:
        cards = '<div class="box">No packages published yet.</div>'

    pay_lines = []
    for c in cfgs:
        if c.till_number:
            pay_lines.append(f"M-Pesa Till: <b>{html_escape(c.till_number)}</b>")
        elif c.paybill_number:
            pay_lines.append(f"PayBill: <b>{html_escape(c.paybill_number)}</b> (Acct: {html_escape(c.account_reference)})")
        elif c.instructions:
            pay_lines.append(html_escape(c.instructions))
    pay_info = "<br>".join(pay_lines) or "Contact customer care for payment details."

    return (
        PORTAL_SHELL.replace("__BIZ__", html_escape(t.business_name))
        .replace("__PHONE__", html_escape(t.owner_phone))
        .replace("__CARDS__", cards)
        .replace("__PAYINFO__", pay_info)
        .replace("__SLUG__", html_escape(t.slug))
    )


@router.post(f"{API_V1_PREFIX}/portal/{{slug}}/redeem-voucher")
def portal_redeem_voucher(slug: str, body: VoucherRedeemIn, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.slug == slug.lower().strip()).first()
    if not t or t.status == "SUSPENDED":
        raise HTTPException(status_code=404, detail="ISP portal unavailable")
    code = body.code.strip().upper()
    v = db.query(Voucher).filter(Voucher.tenant_id == t.id, Voucher.code == code).first()
    if not v or v.status != "UNUSED" or v.uses_count >= v.max_uses:
        raise HTTPException(status_code=400, detail="Voucher invalid or already redeemed")
    if v.expires_at:
        v_exp = v.expires_at if v.expires_at.tzinfo else v.expires_at.replace(tzinfo=timezone.utc)
        if v_exp < utcnow():
            raise HTTPException(status_code=400, detail="Voucher expired")

    # Atomic duplicate-redemption protection
    updated = db.query(Voucher).filter(Voucher.id == v.id, Voucher.uses_count < Voucher.max_uses, Voucher.status == "UNUSED").update({"uses_count": Voucher.uses_count + 1})
    if updated == 0:
        db.rollback()
        raise HTTPException(status_code=409, detail="Voucher already redeemed")

    v = db.query(Voucher).filter(Voucher.id == v.id).first()
    if v.uses_count >= v.max_uses:
        v.status = "REDEEMED"

    pkg = db.query(InternetPackage).filter(InternetPackage.id == v.package_id).first()
    exp = utcnow() + timedelta(minutes=pkg.duration_minutes if pkg else 60)
    acct = "VCH" + secrets.token_hex(3).upper()
    cust = Customer(
        tenant_id=t.id, package_id=v.package_id, account_number=acct,
        full_name="Voucher User", phone=body.phone.strip() or "N/A",
        connection_type="HOTSPOT", username=code, secret_enc=encrypt_secret(code),
        status="ACTIVE", expires_at=exp,
    )
    db.add(cust)
    db.flush()
    db.add(VoucherRedemption(tenant_id=t.id, voucher_id=v.id, customer_id=cust.id, mac_address=body.mac_address))
    db.commit()
    return {"status": "ACTIVE", "username": cust.username, "package": pkg.name if pkg else "", "expires_at": exp.isoformat()}


@router.post(f"{API_V1_PREFIX}/portal/{{slug}}/reconnect")
def portal_reconnect(slug: str, body: ReconnectIn, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.slug == slug.lower().strip()).first()
    if not t:
        raise HTTPException(status_code=404, detail="ISP portal not found")
    ident = body.identifier.strip()
    c = db.query(Customer).filter(Customer.tenant_id == t.id, (Customer.phone == ident) | (Customer.account_number == ident) | (Customer.username == ident)).order_by(Customer.created_at.desc()).first()
    if not c:
        raise HTTPException(status_code=404, detail="Account not found")
    if not c.expires_at:
        raise HTTPException(status_code=400, detail="No active package")
    exp = c.expires_at if c.expires_at.tzinfo else c.expires_at.replace(tzinfo=timezone.utc)
    if exp <= utcnow():
        c.status = "EXPIRED"
        db.commit()
        raise HTTPException(status_code=402, detail="Package expired; please purchase a new package")
    c.status = "ACTIVE"
    db.commit()
    return {"status": "ACTIVE", "username": c.username, "expires_at": exp.isoformat()}


# ==========================================================
# MILESTONE 3 SELF-TEST SUITE
# ==========================================================

def run_m3_tests():
    from fastapi.testclient import TestClient
    _m.run_stage_tests()  # Run Stages 1-6 tests first
    with TestClient(_m.app) as client:
        tok_a = client.post(f"{API_V1_PREFIX}/auth/isp/login", json={"tenant_slug": "savanna", "email": "ali@savanna.ke", "password": "IspPass#2026"}).json()["access_token"]
        tok_b = client.post(f"{API_V1_PREFIX}/auth/isp/login", json={"tenant_slug": "rift", "email": "joy@rift.ke", "password": "IspPass#2026"}).json()["access_token"]
        ha, hb = {"Authorization": f"Bearer {tok_a}"}, {"Authorization": f"Bearer {tok_b}"}

        # 1. Compatibility & Honest Unreachable Router Probe
        crs_warn = evaluate_compatibility("CRS326", "7.15", api_ok=True)
        assert any("CRS" in w for w in crs_warn["warnings"])
        r_id = client.post(f"{API_V1_PREFIX}/isp/routers", headers=ha, json={"name": "Main-RB750", "host": "127.0.0.1", "api_port": 59999, "password": "pass"}).json()["id"]
        probe = client.post(f"{API_V1_PREFIX}/isp/routers/{r_id}/test", headers=ha).json()
        assert probe["online"] is False and probe["compatibility"]["compatible"] is False

        # 2. RouterOS v7 Script Generation + Download
        sc = client.post(f"{API_V1_PREFIX}/isp/routers/{r_id}/script", headers=ha, json={"model": "RB750Gr3", "ros_version": "7", "mode": "API"}).json()
        assert "prime-hotspot-preinstall" in sc["script"] and "/system backup load" in sc["script"]
        assert client.get(f"{API_V1_PREFIX}/isp/routers/{r_id}/script/download", headers=hb).status_code == 404  # Cross-tenant isolated

        # 3. Packages + Customers (Hotspot & PPPoE)
        pkgs = client.get(f"{API_V1_PREFIX}/isp/packages", headers=ha).json()
        pkg_id = pkgs[0]["id"]
        pppoe_pkg = client.post(f"{API_V1_PREFIX}/isp/packages", headers=ha, json={"service_type": "PPPOE", "name": "Home 10M", "price": 2000, "duration_minutes": 43200}).json()["id"]
        assert client.post(f"{API_V1_PREFIX}/isp/customers", headers=ha, json={"full_name": "John Doe", "phone": "0711000111", "connection_type": "PPPOE", "package_id": pppoe_pkg, "router_id": r_id}).status_code == 200

        # 4. Bulk Vouchers + Duplicate Redemption Protection + Captive Portal Reconnect
        v_res = client.post(f"{API_V1_PREFIX}/isp/vouchers/generate", headers=ha, json={"package_id": pkg_id, "quantity": 5, "prefix": "SAV-"}).json()
        assert v_res["generated"] == 5
        code = v_res["codes"][0]
        assert client.post(f"{API_V1_PREFIX}/portal/savanna/redeem-voucher", json={"code": code, "phone": "0722333444"}).status_code == 200
        assert client.post(f"{API_V1_PREFIX}/portal/savanna/redeem-voucher", json={"code": code, "phone": "0722333444"}).status_code == 400  # Duplicate blocked
        assert client.post(f"{API_V1_PREFIX}/portal/savanna/reconnect", json={"identifier": "0722333444"}).json()["status"] == "ACTIVE"
        assert "Savanna WiFi" in client.get("/portal/savanna").text

    print("ALL STAGES 7-11, 16-17 TESTS PASSED (RouterOS API/Probe, Scripts, Hotspot/PPPoE, Vouchers, Captive Portal).")


if __name__ == "__main__":
    if "--test" in sys.argv:
        run_m3_tests()
