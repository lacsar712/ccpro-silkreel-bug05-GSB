from datetime import datetime, timedelta, timezone

import jwt
from werkzeug.security import check_password_hash, generate_password_hash

from app.config import JWT_ALG, JWT_SECRET


def hash_password(plain: str) -> str:
    return generate_password_hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return check_password_hash(hashed, plain)


SESSION_EPOCH = 0


def bump_session_epoch() -> int:
    global SESSION_EPOCH
    SESSION_EPOCH += 1
    return SESSION_EPOCH


def make_token(username: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=12)
    return jwt.encode(
        {"sub": username, "exp": exp, "epoch": SESSION_EPOCH},
        JWT_SECRET,
        algorithm=JWT_ALG,
    )


def parse_token(token: str, check_epoch: bool = True) -> str | None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        if check_epoch and payload.get("epoch", 0) != SESSION_EPOCH:
            return None
        return payload.get("sub")
    except jwt.PyJWTError:
        return None
