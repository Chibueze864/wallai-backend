from sqlalchemy import Column, Integer, String, Date, Numeric, Enum, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
import enum

class ExpenseCategory(enum.Enum):
    FURNISHINGS = "Furnishings"
    PROPERTY_TAXES = "Property Taxes"
    EMERGENCY_FUND = "Emergency Fund"
    GAS = "Gas"
    FOOD = "Food"
    CAR_REPAIRS = "Car Repairs"
    TRANSPORTATION = "Transportation"
    CHILD_CARE = "Child Care"
    INSURANCE = "Insurance"
    HOUSING = "Housing"
    ENTERTAINMENT = "Entertainment"
    HEALTHCARE = "Healthcare"
    HOUSING_EXPENSES = "Housing Expenses"
    CLOTHING = "Clothing"

class ExpenseStatus(enum.Enum):
    COMPLETED = "Completed"
    PENDING = "Pending"
    CANCELLED = "Cancelled"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    expenses = relationship("Expense", back_populates="user")

class Expense(Base):
    __tablename__ = "expenses"
    id = Column(String(50), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    date = Column(Date, nullable=False)
    amount = Column(Numeric(10, 2), nullable=False)
    category = Column(Enum(ExpenseCategory), nullable=False)
    status = Column(Enum(ExpenseStatus), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="expenses")
