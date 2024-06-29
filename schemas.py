from pydantic import BaseModel
from datetime import date
from typing import List
from decimal import Decimal

class ExpenseBase(BaseModel):
    name: str
    date: date
    amount: Decimal
    category: str
    status: str

class ExpenseCreate(BaseModel):
    name: str
    date: date
    amount: Decimal
    category: str
    status: str

class Expense(ExpenseBase):
    id: str
    user_id: int

    class Config:
        orm_mode = True

class FinancialEntry(BaseModel):
    id: str
    name: str
    date: str
    amount: str
    category: str
    status: str

class FinancialAnalysisRequest(BaseModel):
    data: List[FinancialEntry]

class FinancialAnalysisResponse(BaseModel):
    income_analysis: str
    spending_analysis: str
    savings_recommendations: str
    overspending_adjustments: str
    
class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    expenses: List[Expense] = []

    class Config:
        orm_mode = True
