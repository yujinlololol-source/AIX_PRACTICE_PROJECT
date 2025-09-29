# FastAPI 세팅
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from typing import List
from sqlalchemy import select
from datetime import datetime

# 암복호화
import bcrypt

# modules 객체 import
from db import Base, UserInfo

# schemas 객체 import
from db import UserBase, UserCreate, UserRead, UserUpdate, UserDelete, UserPwUpdate, UserLogin

# database 객체 import
from db import engine, session_factory

# =====================================================================================================================================

# create_all 처리
Base.metadata.create_all(bind = engine)

app = FastAPI()

# CORS 설정
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

# =====================================================================================================================================

# get = read
@app.get("/userInfo", response_model = List[UserBase])
def user_info():
    with session_factory() as db:
        # UserInfo 기반 데이터 select
        stmt = select(UserInfo)

        # 모든 데이터 가져오기 왜? 정보 확인 페이지니까
        query = db.execute(stmt).scalars().all()

        return query
    
# =====================================================================================================================================
# get = read_user (특정 유저 조회)
@app.get("/userInfo/{no_seq}", response_model = UserRead)
def user_read(no_seq : int):
    with session_factory() as db:
        # no_seq로 특정 유저 정보 조회
        stmt = select(UserInfo).where(UserInfo.no_seq == no_seq)
        query = db.execute(stmt).scalar_one_or_none()
        
        # 해당 no_seq의 유저가 없으면
        if not query:
            raise HTTPException(status_code=404, detail="일치한 회원 정보가 없습니다.")
        
        return query

# =====================================================================================================================================

# post = create
@app.post("/userCreate", response_model = UserCreate)
def user_create(data : UserCreate):
    with session_factory() as db:
        # 비밀번호 암호화
        encrypt_user_pw = bcrypt.hashpw(
            data.user_pw.get_secret_value().encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        # 데이터 세팅
        db_user = UserInfo(
            user_id = data.user_id,
            user_pw = encrypt_user_pw,
            user_email = data.user_email,
            user_addr1 = data.user_addr1,
            user_addr2 = data.user_addr2,
            user_post = data.user_post,
            user_birth = data.user_birth,
            user_create_date = datetime.now(),
            user_delete_yn = "N"
        )
        
        # 세션에 db_user(데이터 세팅 변수) 추가
        db.add(db_user)

        # 세션 저장(commit)
        db.commit()

        # 세션 새로고침(python 정보)
        db.refresh(db_user)

        return db_user
    
# =====================================================================================================================================

# 부분 수정 - patch
@app.patch("/userPwUpdate/{no_seq}")
def user_pw_update(no_seq : int, data : UserPwUpdate):
    with session_factory() as db:
        # 유저의 정보 가져오기(암호화 되어있음)
        stmt = select(UserInfo).where(UserInfo.no_seq == no_seq)
        query = db.execute(stmt).scalar_one_or_none()

        # no_seq의 회원의 데이터가 없으면
        if not query:
            raise HTTPException(status_code=404, detail="일치한 회원 정보가 없습니다.")

        # 입력된 현재 비밀번호 검증
        if not bcrypt.checkpw(data.now_user_pw.get_secret_value().encode("utf-8"), query.user_pw.encode("utf-8")):
            raise HTTPException(status_code = 400, detail = "현재 비밀번호가 일치하지 않습니다.")

        # 새로운 비번 암호화
        encrypt_new_user_pw = bcrypt.hashpw(
            data.new_user_pw.get_secret_value().encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        # 일치하는 no_seq 회원의 비번을 새롭게 암호화한 비번으로 변경
        query.user_pw = encrypt_new_user_pw
        db.commit()
        db.refresh(query)
        
        return {"msg" : "비밀번호가 정상적으로 변경 되었습니다."}

# =====================================================================================================================================

# 간단한 로그인 테스트
@app.post("/userLogin", response_model = UserBase)
def user_login(data : UserLogin):
    with session_factory() as db:
        # 아이디로 유저 검색
        stmt = select(UserInfo).where(UserInfo.user_id == data.user_id)
        query = db.execute(stmt).scalar_one_or_none()

        # 만약 id가 존재하지 않으면
        if not query:
            raise HTTPException(status_code = 404, detail = "일치한 아이디 정보가 없습니다.")

        # 여까지 넘어오면 아이디는 있다는 거 > 비번 검증 시작
        if not bcrypt.checkpw(data.user_pw.get_secret_value().encode("utf-8"), query.user_pw.encode("utf-8")):
            raise HTTPException(status_code = 400, detail = "비밀번호가 일치하지 않습니다.")
        

        return query

