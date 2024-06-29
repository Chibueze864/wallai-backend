from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List, Dict
from datetime import datetime, timedelta
import jwt
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from database import SessionLocal, engine
import models, schemas
from models import User, Expense, ExpenseCategory, ExpenseStatus
import uuid
import google.generativeai as genai
import logging

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

logging.basicConfig(level=logging.INFO)
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Configure Gemini API
genai.configure(api_key="AIzaSyCbYe-M5c_qOmiTr4K9UlqJe4o004F3EUE")
model = genai.GenerativeModel('gemini-1.5-flash')


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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
    except PyJWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


# User endpoints
@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Expense endpoints
@app.post("/expenses/", response_model=schemas.Expense)
async def create_expense(
    expense: schemas.ExpenseCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        db_expense = Expense(
            id=str(uuid.uuid4()),
            name=expense.name,
            date=expense.date,
            amount=expense.amount,
            category=ExpenseCategory[expense.category],
            status=ExpenseStatus[expense.status],
            user_id=current_user.id
        )
        db.add(db_expense)
        db.commit()
        db.refresh(db_expense)
        return db_expense
    except Exception as e:
        db.rollback()
        print(f"Error creating expense: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@app.get("/expenses/", response_model=List[schemas.Expense])
async def read_expenses(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    expenses = db.query(Expense).filter(Expense.user_id == current_user.id).offset(skip).limit(limit).all()
    return expenses

@app.get("/expenses/{expense_id}", response_model=schemas.Expense)
async def read_expense(
    expense_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    expense = db.query(Expense).filter(Expense.id == expense_id, Expense.user_id == current_user.id).first()
    if expense is None:
        raise HTTPException(status_code=404, detail="Expense not found")
    return expense

@app.put("/expenses/{expense_id}", response_model=schemas.Expense)
async def update_expense(
    expense_id: str,
    expense: schemas.ExpenseCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        db_expense = db.query(Expense).filter(Expense.id == expense_id, Expense.user_id == current_user.id).first()
        if db_expense is None:
            raise HTTPException(status_code=404, detail="Expense not found")
        
        db_expense.name = expense.name
        db_expense.date = expense.date
        db_expense.amount = expense.amount
        db_expense.category = ExpenseCategory[expense.category]
        db_expense.status = ExpenseStatus[expense.status]
        
        db.add(db_expense)
        db.commit()
        db.refresh(db_expense)
        return db_expense
    except KeyError as ke:
        db.rollback()
        print(f"KeyError: {str(ke)}")
        raise HTTPException(status_code=400, detail=f"Invalid category or status: {str(ke)}")
    except Exception as e:
        db.rollback()
        print(f"Error updating expense: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@app.delete("/expenses/{expense_id}", response_model=schemas.Expense)
async def delete_expense(
    expense_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    expense = db.query(Expense).filter(Expense.id == expense_id, Expense.user_id == current_user.id).first()
    if expense is None:
        raise HTTPException(status_code=404, detail="Expense not found")
    db.delete(expense)
    db.commit()
    return expense



def preprocess_data(data: List[schemas.FinancialEntry]) -> Dict:
    """Preprocess and aggregate financial data."""
    income = 0
    expenses = 0
    categories = {}
    
    for entry in data:
        amount = float(entry.amount.replace('₹', '').replace(',', ''))
        if entry.category.lower() == 'income':
            income += amount
        else:
            expenses += amount
            categories[entry.category] = categories.get(entry.category, 0) + amount
    
    return {
        "total_income": income,
        "total_expenses": expenses,
        "expense_categories": categories
    }

@app.post("/analyze-finances/")
async def analyze_finances_route(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyze financial data and provide insights.
    This endpoint requires authentication.
    """
    logging.info(f"Analyzing finances for user: {current_user.email}")
    try:
        # Fetch user's expenses from the database
        user_expenses = db.query(Expense).filter(Expense.user_id == current_user.id).all()
        logging.info(f"Found {len(user_expenses)} expenses for user")

        # Convert expenses to FinancialEntry format
        financial_entries = [
            schemas.FinancialEntry(
                id=str(expense.id),
                name=expense.name,
                date=str(expense.date),
                amount=f"₹{expense.amount:.2f}",
                category=expense.category.value,
                status=expense.status.value
            ) for expense in user_expenses
        ]

        # Preprocess the data
        preprocessed_data = preprocess_data(financial_entries)

        # Prepare the prompt for Gemini model
        prompt = f"""
        Analyze the following financial data:
        Total Income: ₹{preprocessed_data['total_income']}
        Total Expenses: ₹{preprocessed_data['total_expenses']}
        Expense Categories:
        {preprocessed_data['expense_categories']}
        Please provide:
        1. An analysis of income and past spending patterns
        2. Recommendations for savings goals based on the financial situation
        3. Suggestions for adjustments to avoid overspending
        Format your response as follows:
        INCOME_AND_SPENDING_ANALYSIS:
        [Your analysis here]
        SAVINGS_RECOMMENDATIONS:
        [Your recommendations here]
        OVERSPENDING_ADJUSTMENTS:
        [Your suggestions here]
        Be specific and provide actionable insights based on the data.
        """

        # Generate content using Gemini model
        response = model.generate_content(prompt)
        response_text = response.text

        # Parse the response
        sections = response_text.split('\n\n')
        income_analysis = sections[0].replace('INCOME_AND_SPENDING_ANALYSIS:', '').strip()
        savings_recommendations = sections[1].replace('SAVINGS_RECOMMENDATIONS:', '').strip()
        overspending_adjustments = sections[2].replace('OVERSPENDING_ADJUSTMENTS:', '').strip()

        # Prepare and return the response
        return schemas.FinancialAnalysisResponse(
            income_analysis=income_analysis,
            spending_analysis=income_analysis,  # Included in the same section
            savings_recommendations=savings_recommendations,
            overspending_adjustments=overspending_adjustments
        )

    except Exception as e:
        logging.error(f"Error in analyze_finances_route: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error analyzing finances: {str(e)}")
