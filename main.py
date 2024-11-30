from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from schemas import UserCreate, UserResponse
from curd import create_user, get_user_by_email
from auth import oauth2_scheme, create_access_token
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from auth import SECRET_KEY, ALGORITHM,pwd_context




Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility function to decode and verify the token
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid email")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token get")

@app.post("/users/", response_model=UserResponse)
def create_new_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return create_user(db=db, user=user)

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_email(db, email=form_data.username)
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Route to verify login and redirect
@app.get("/verify-login")
def verify_login(token: str = Depends(oauth2_scheme)):
    email = verify_token(token)
    return RedirectResponse(url=f"/dashboard/{email}")

# Dashboard route (after successful login)
@app.get("/dashboard/{email}")
def dashboard(email: str, token: str = Depends(oauth2_scheme)):
    user_email = verify_token(token)
    if user_email != email:
        raise HTTPException(status_code=403, detail="Access forbidden")
    return {"message": f"Welcome to your dashboard, {email}"}


# Additional protected route
@app.get("/profile")
def profile(token: str = Depends(oauth2_scheme)):
    email = verify_token(token)
    return {"message": f"This is the profile page for {email}"}

# Public route
@app.get("/")
def public():
    return {"message": "Welcome to the public route!"}
