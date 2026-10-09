MEDIA = "/media"  # the owner's files (Runtipi media folder), mounted read-only
AUDIO_MAX = 512 * 1024 * 1024
DEFAULT_MODEL = os.environ.get("TRANSCRIBER_MODEL", "")


def _media_path(path):
    full = os.path.realpath(os.path.join(MEDIA, str(path).lstrip("/")))
    if full != MEDIA and not full.startswith(MEDIA + "/"):
        raise ValueError("path must be inside the owner's files")
    if not os.path.isfile(full):
        raise FileNotFoundError("no file at %s (paths are relative to the Files root, e.g. Videos/talk.mp4)" % path)
    if os.path.getsize(full) > AUDIO_MAX:
        raise ValueError("file is larger than 512 MB")
    return full


def _multipart(fields, filename, data):
    boundary = uuid.uuid4().hex
    out = []
    for k, v in fields:
        out.append(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (boundary, k, v)).encode())
    out.append(('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n'
                % (boundary, os.path.basename(filename).replace('"', ""))).encode())
    out.append(data)
    out.append(("\r\n--%s--\r\n" % boundary).encode())
    return b"".join(out), "multipart/form-data; boundary=" + boundary


@tool("transcribe", "Transcribe an audio or video file from the owner's files to text, optionally with word timings. "
      "Runs locally; nothing leaves the box.",
      {"path": {"type": "string", "description": "File path relative to the Files root, e.g. Videos/talk.mp4"},
       "language": {"type": "string", "description": "ISO code such as en; omit to auto-detect"},
       "word_timestamps": {"type": "boolean", "description": "Include per-word start/end times (default false)"},
       "model": {"type": "string", "description": "Model id; defaults to the one this app preloads"}},
      ["path"])
def transcribe(path, language=None, word_timestamps=False, model=None):
    full = _media_path(path)
    fields = [("model", model or DEFAULT_MODEL), ("response_format", "verbose_json")]
    if language:
        fields.append(("language", language))
    if word_timestamps:
        fields.append(("timestamp_granularities[]", "word"))
    fields.append(("timestamp_granularities[]", "segment"))
    with open(full, "rb") as f:
        body, ctype = _multipart(fields, full, f.read())
    _, raw = http("POST", "/v1/audio/transcriptions", body, {"Content-Type": ctype}, timeout=3600)
    d = json.loads(raw)
    out = {"text": d.get("text", ""), "language": d.get("language"), "duration": d.get("duration")}
    if word_timestamps:
        out["words"] = [{"word": w.get("word"), "start": w.get("start"), "end": w.get("end")} for w in d.get("words") or []]
    else:
        out["segments"] = [{"start": s.get("start"), "end": s.get("end"), "text": s.get("text")} for s in d.get("segments") or []]
    return out


@tool("transcriber_status", "Check the Transcriber is up and list the speech models it has downloaded.")
def transcriber_status():
    _, raw = http("GET", "/v1/models", timeout=30)
    models = [m.get("id") for m in json.loads(raw).get("data") or []]
    return {"ok": True, "default_model": DEFAULT_MODEL, "models": models,
            "api": "OpenAI-compatible /v1/audio/transcriptions on this app's address"}
