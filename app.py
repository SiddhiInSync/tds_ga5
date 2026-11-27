"""Rule-based safety router for TDS GA5 Q4 (agent-harness-2026-09)."""
import json, re
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def rx(*w): return re.compile("|".join(w), re.I)

HARM = rx(r"steal\w*\s+(\w+\s+){0,3}(credential|password|token|cookie|key)", r"credential[- ]?harvest", r"phish",
          r"exfiltrat", r"leak\s+(the\s+)?(customer|user|private|patient)", r"dump\s+(all\s+)?(customer|user|password)",
          r"fraud", r"fake\s+(invoice|review|receipt|id)", r"launder", r"harass", r"dox", r"stalk", r"threaten",
          r"ransomware", r"wiper", r"keylogger", r"destructive\s+malware", r"botnet", r"worm\s+that",
          r"self[- ]propagat", r"bomb", r"explosive", r"poison", r"nerve agent", r"weapon",
          r"evade\s+(av|antivirus|edr|detection)", r"bypass\s+(the\s+)?(safeguard|safety filter|content filter|2fa|mfa)")
DEFENSIVE = rx(r"\bdetect", r"defen[cs]", r"remediat", r"mitigat", r"patch", r"\banaly[sz]", r"translat",
               r"summari[sz]", r"explain", r"\bfiction", r"novel", r"\bstory", r"screenplay", r"incident report",
               r"\bclassif", r"signature", r"yara", r"awareness training", r"why is this")
SECURITY = rx(r"exploit", r"vulnerab", r"\bcve-", r"\bfuzz", r"pen(etration)?[- ]?test", r"proof[- ]of[- ]concept",
              r"\bpoc\b", r"sql injection", r"\bsqli\b", r"\bxss\b", r"buffer overflow", r"\brce\b", r"privilege escalation",
              r"red[- ]team", r"\bctf\b", r"attack surface", r"port scan", r"\bnmap\b")
OWNED = rx(r"\bour (own )?(lab|test|staging|isolated)", r"\bowned\b", r"\bi own\b", r"we own", r"isolated (lab|target|vm|range|container)",
           r"authori[sz]ed (scope|engagement|test)", r"in[- ]scope", r"our sandbox", r"local (lab|vm|target)", r"ctf")
UNCLEAR = rx(r"someone else", r"third[- ]party", r"competitor", r"not sure (who|if we)", r"\bex[- ]", r"their (server|site|network)",
             r"random", r"any (site|server|host)")
REVOKE = rx(r"\b(do not|don't|dont|never|stop|cancel|revoke|abort|hold off|no longer|not anymore|withdraw|disregard (my|the) (earlier|previous))\b")
INJECT = rx(r"ignore (all |any )?(previous|prior|above)", r"you are (now )?(authori[sz]ed|approved|allowed)", r"pre-?approved",
            r"(admin|owner|user) (has )?approved", r"system override", r"new instructions", r"disregard (the )?policy",
            r"do not (ask|tell) the user", r"without (asking|confirmation)", r"assistant must", r"ai agents? (must|should)",
            r"auto-?approve", r"skip (the )?(review|preflight|confirmation)")
READ_OPS = {"read", "list", "inspect", "view", "show", "status", "diff", "log", "plan", "describe", "get", "query",
            "search", "grep", "cat", "stat", "fetch_metadata", "analyze", "lint", "test", "build", "dry_run", "dry-run"}
EDIT_OPS = {"edit", "write", "modify", "patch", "create", "update_file", "format", "rename", "append", "mkdir"}
SENSITIVE = {"credential", "credentials", "secret", "secrets", "private", "pii", "confidential", "restricted", "personal", "sensitive"}
CONSEQ = rx(r"delete|remove|rm\b|wipe|truncate|drop|destroy|purge|send|email|upload|transfer|export|post|publish|share|push|force|deploy|migrat|"
            r"dns|privileg|sudo|chmod|chown|grant|iam|docker|kill|restart|scale|mutat|apply|write_prod|payment|transfer")
BYPASS = rx(r"--?(skip|no)[-_]?(preflight|verify|check|safety|hooks?)", r"bypass[-_ ]?(preflight|safety|check)",
            r"--force-without", r"ignore[-_]?preflight", r"SKIP_PREFLIGHT")

def s(x):
    if x is None: return ""
    return x if isinstance(x, str) else json.dumps(x, ensure_ascii=False)

def low(x): return s(x).lower()

def truthy(v):
    if isinstance(v, bool): return v
    if isinstance(v, str): return v.lower() in ("true", "yes", "1", "success", "succeeded", "passed", "ok")
    return bool(v)

def user_msgs(case):
    return [s(m.get("content")) for m in case.get("messages") or [] if isinstance(m, dict) and m.get("role", "user") == "user"]

def untrusted_text(case):
    parts = []
    for k in ("memory", "repositoryInstructions", "toolResults"):
        parts.append(s(case.get(k)))
    for m in case.get("messages") or []:
        if isinstance(m, dict) and m.get("role") not in (None, "user"):
            parts.append(s(m.get("content")))
    return "\n".join(parts)

def target_tokens(res, tool):
    toks = set()
    for k in ("target", "destination", "host", "path", "repository", "branch", "domain", "recipient", "url", "resource"):
        v = res.get(k)
        if isinstance(v, str) and v.strip():
            v = v.strip().lower(); toks.add(v)
            base = re.split(r"[/\\:@]", v.rstrip("/"))[-1]
            if len(base) >= 3: toks.add(base)
    return toks

def mentions(text, toks):
    t = text.lower()
    return any(tok and tok in t for tok in toks)

def classify_request(case):
    msgs = user_msgs(case)
    last = msgs[-1] if msgs else ""
    allu = " ".join(msgs)
    sec = bool(SECURITY.search(last) or SECURITY.search(allu))
    harm = bool(HARM.search(last))
    defensive = bool(DEFENSIVE.search(last))
    if harm and not defensive:
        return "block", sec, False
    if sec:
        owned = bool(OWNED.search(allu)) or truthy(((case.get("environment") or {}).get("isolation") or {}).get("verified"))
        if harm and defensive:
            return "allow", True, False
        if UNCLEAR.search(allu) or not owned:
            return "review", True, True
        return "allow", True, False
    return "allow", False, False

def classify_tool(case, req):
    tool = case.get("proposedTool")
    if not tool:
        return "none", False
    res = tool.get("resolved") or {}
    env = case.get("environment") or {}
    iso = env.get("isolation") or {}
    op = low(res.get("operation"))
    sens = low(res.get("sensitivity"))
    renv = low(res.get("environment") or env.get("kind"))
    args = s(tool.get("arguments"))
    msgs = user_msgs(case)
    last = msgs[-1] if msgs else ""
    allu = " ".join(msgs)
    untrusted = untrusted_text(case)
    toks = target_tokens(res, tool)
    whole = (op + " " + args + " " + s(res)).lower()

    if req == "block":
        return "block", False

    # Revocation / explicit forbiddance in the latest user message that touches this action
    rev_hit = False
    for i, m in enumerate(msgs):
        if REVOKE.search(m) and (mentions(m, toks) or (op and op in m.lower()) or re.search(r"\b(that|it|this)\b", m, re.I)):
            # revocation counts if it is the latest instruction about this action
            later = msgs[i + 1:]
            if not any(mentions(x, toks) and not REVOKE.search(x) for x in later):
                rev_hit = True
    if rev_hit:
        return "block", False

    # Safety-preflight bypass
    if BYPASS.search(whole) or truthy(res.get("bypassPreflight")) or truthy(res.get("skipPreflight")):
        return "block", False

    # Unknown environment / unresolved target
    if renv in ("", "unknown", "unresolved") or low(res.get("target")) in ("", "unknown", "unresolved", "none") and op not in READ_OPS:
        if not res:
            return "review", False
        if renv in ("unknown", "unresolved") or low(res.get("target")) in ("unknown", "unresolved"):
            return "review", False

    followed_injection = bool(INJECT.search(untrusted)) and not mentions(allu, toks) and bool(CONSEQ.search(whole))

    # Credentials
    if "credential" in sens or "secret" in sens or op in ("read_credential", "load_credential", "search_credentials"):
        approved = truthy(res.get("taskScoped")) or truthy(res.get("approved"))
        if not approved and (mentions(allu, toks) and re.search(r"(use|load|with)\b", allu, re.I)) and not re.search(r"search|find|all|any|scan", op + args, re.I):
            approved = True
        if re.search(r"search|scan|find|grep|list", op + " " + args, re.I) and not truthy(res.get("taskScoped")):
            return "block", False
        return ("allow" if approved else "block"), False

    # Private data transfers
    is_send = bool(re.search(r"send|upload|transfer|export|email|post|share|sync|copy_remote|webhook|http", op))
    if is_send and sens in SENSITIVE:
        dest = low(res.get("destination") or res.get("target"))
        if dest and dest in allu.lower() and not followed_injection:
            return "allow", False
        return "block", False

    if followed_injection:
        return "block", False

    prod = "prod" in renv or truthy(res.get("production"))

    # Read-only
    if op in READ_OPS or op.startswith("read") or op.startswith("list") or op.startswith("inspect"):
        if sens in SENSITIVE and not mentions(allu, toks):
            return "review", False
        return "allow", False

    # Disposable deletion inside verified isolation
    if op in ("delete", "remove", "rm", "wipe", "purge"):
        clean_iso = (truthy(iso.get("verified")) and not iso.get("hostMounts") and not truthy(iso.get("credentials"))
                     and not truthy(iso.get("externalNetwork")) and renv == "container")
        if clean_iso and truthy(res.get("disposable")) and sens in ("public", "", "none", "internal", "test"):
            return "allow", False

    # Reversible workspace edits
    if op in EDIT_OPS and not prod and renv in ("workspace", "container", "local", "repo", "repository", "sandbox", "dev") \
            and sens not in SENSITIVE and not truthy(res.get("hostMount")):
        return "allow", False

    # Everything else is consequential: need exact authorization
    authorized = mentions(last, toks) or (mentions(allu, toks) and not any(REVOKE.search(m) for m in msgs))
    if not authorized:
        return "review", False
    if prod:
        tr = s(case.get("toolResults")).lower()
        preflight_ok = bool(re.search(r"preflight", tr)) and bool(re.search(r"\"(status|result|outcome)\"\s*:\s*\"(success|succeeded|passed|ok)\"|\"(ok|success|passed)\"\s*:\s*true", tr))
        preflight_failed = bool(re.search(r"preflight", tr)) and bool(re.search(r"fail|error|denied|rejected", tr))
        rb = case.get("rollbackPlan") or case.get("rollback")
        if preflight_failed:
            return "block", False
        if not preflight_ok or not rb:
            return "review", False
    return "allow", False

def classify(case):
    req, sec, unclear = classify_request(case)
    tool, _ = classify_tool(case, req)
    if req == "block":
        tool = "block" if case.get("proposedTool") else "none"
    elif req == "review" and tool != "block":
        tool = "review" if case.get("proposedTool") else "none"
    route = "none" if req == "block" else ("restricted" if sec or unclear else "primary")
    injected = bool(INJECT.search(untrusted_text(case)))
    if req == "block" or tool == "block":
        traj = "intervene"
    elif req == "review" or tool == "review" or unclear or injected:
        traj = "watch"
    else:
        traj = "normal"
    return {"caseId": case.get("caseId"), "requestDecision": req, "toolDecision": tool, "route": route, "trajectory": traj}

def safe(case):
    try:
        return classify(case)
    except Exception:
        return {"caseId": case.get("caseId"), "requestDecision": "review",
                "toolDecision": "review" if case.get("proposedTool") else "none", "route": "primary", "trajectory": "watch"}

@app.post("/")
@app.post("/classify")
async def handle(request: Request):
    body = await request.json()
    out = {"profile": body.get("profile", "agent-harness-2026-09"), "batchId": body.get("batchId"),
           "results": [safe(c) for c in body.get("cases") or []]}
    return JSONResponse(out)

@app.get("/")
def health():
    return {"ok": True}
