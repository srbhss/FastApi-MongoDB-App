from datetime import datetime, timedelta
import jwt
import bcrypt
from pydantic import BaseModel, EmailStr
from fastapi import Depends, APIRouter, HTTPException, status
from db.database import AsyncIOMotorClient, get_database, database_name, users_collection_name, comments_collection_name
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import PyJWTError
from passlib.context import CryptContext
from starlette.exceptions import HTTPException
from starlette.status import HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

router = APIRouter()

SECRET_KEY = "secret key for project"
ALGORITHM = "HS256"
JWT_TOKEN_PREFIX = "Token"


class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    email: EmailStr

class DBUser(User):
    password : str

class Comment(User):
    text: str



async def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def get_password_hash(password):
    salt = bcrypt.gensalt().decode()
    return pwd_context.hash(salt + password)


async def get_user(conn: AsyncIOMotorClient, email: EmailStr) -> User:
    row = await conn[database_name][users_collection_name].find_one({"email": email})
    if row:
        return User(**row)


async def create_user(conn: AsyncIOMotorClient, user: DBUser) -> User:
    row = await conn[database_name][users_collection_name].insert_one(user.dict())
    return User(**row)


async def create_comment(conn: AsyncIOMotorClient, comment: Comment) -> Comment:
    row = await conn[database_name][comments_collection_name].insert_one(comment.dict())
    return Comment(**row)


async def authenticate_user(conn: AsyncIOMotorClient, email: EmailStr, password: str):
    user = get_user(conn, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


async def create_access_token(*, email: EmailStr, expires_delta: timedelta = None):
    data: dict = {"sub":email}
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def _get_authorization_token(authorization: str):
    token_prefix, token = authorization.split(" ")
    if token_prefix != JWT_TOKEN_PREFIX:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Invalid authorization type"
        )
    return token


async def get_current_user(conn: AsyncIOMotorClient, token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = Token(email=email)
    except PyJWTError:
        raise credentials_exception
    user = get_user(conn, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user



@router.post("/login/", response_model=Token)
async def login(*, user: DBUser) -> Token:
    conn = get_database()
    user = authenticate_user(conn, email=user.email, password=user.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token = create_access_token(email=user.email)
    token = Token(access_token = access_token, token_type = "bearer")
    return token

@router.post("/signup/")
async def signup(*, user: DBUser) -> User:
    dbuser = DBUser(email=user.email, password=get_password_hash(user.password))
    conn = get_database()
    user =  create_user(conn, dbuser)
    return user

@router.post("/comment/")
async def post_comment(*, authorization: str = Header(...), comment: str ) -> Comment:
    conn: AsyncIOMotorClient
    token = _get_authorization_token(authorization)
    user = get_current_user(conn, token)
    current_user = get_current_active_user(user)
    comment = Comment(email=current_user.email, text=comment)
    comment = create_comment(conn, comment)
    return comment